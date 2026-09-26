// Permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Algorithm (PERMISSIONS.md §3, D1-D10):
//   1. Collect all active grants for (userId, orgId) that are non-revoked and
//      within their time window (starts_at <= now < expires_at).
//   2. For each permission in the catalogue, check:
//      a. Deny wins: if ANY applicable grant denies the permission, result is deny+explicit_deny.
//      b. Allow: if role baseline OR an applicable allow grant covers the permission,
//         result is allow.
//      c. Implicit deny: neither — source=null, reason='implicit'.
//
// "Applicable" for a grant means:
//   - org-wide grant (device_id IS NULL) always applies
//   - device-scoped grant applies only if we're checking for that device
//
// D1: explicit deny always wins, regardless of scope or specificity.
//     An org-wide deny cannot be carved out by a device-scoped allow.
//
// Device permissions (D6): the question always names a device.
// Org-level view = union across all devices (for nav gating, page gating).

import { forbidden, notFound } from './http.js';

// Expand a wildcard pattern against the permission catalogue.
// '*' expands to all permissions; 'device:*' expands to all device:* permissions.
function expandPattern(pattern, allPermissions) {
  if (pattern === '*') return allPermissions;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // 'device:' (keep the colon)
    return allPermissions.filter(p => p.startsWith(prefix));
  }
  // Exact permission — only return if it exists
  return allPermissions.includes(pattern) ? [pattern] : [];
}

// Load all permissions from the database (never hardcode the matrix).
function loadPermissions(db) {
  return db.prepare('SELECT key FROM permissions').all().map(r => r.key);
}

// Load role baseline for a given role.
function loadRoleBaseline(db, role) {
  const rows = db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role);
  return new Set(rows.map(r => r.permission));
}

// Load all active, non-revoked grants with their permissions for a user in an org.
// "Active" = not revoked AND time window applies right now.
function loadActiveGrants(db, userId, orgId, now) {
  const nowIso = now instanceof Date ? now.toISOString() : now;

  const grants = db.prepare(`
    SELECT g.id, g.device_id, g.effect,
           g.starts_at, g.expires_at
    FROM grants g
    WHERE g.user_id = ? AND g.org_id = ?
      AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)
  `).all(userId, orgId, nowIso, nowIso);

  // Attach the permission patterns for each grant
  const stmt = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?');
  return grants.map(g => ({ ...g, patterns: stmt.all(g.id).map(r => r.permission) }));
}

// Core resolution: given the role baseline and active grants, resolve one permission.
// deviceId === null means org-level (union) — we accept any applicable grant.
// deviceId !== null means exact device check — only org-wide or device-specific grants apply.
function resolveOne(permission, roleBaseline, roleName, activeGrants, allPermissions, deviceId) {
  // Collect applicable grants for this question
  const applicableGrants = activeGrants.filter(g => {
    // org-wide grants always apply
    if (g.device_id === null) return true;
    // device-scoped grants only apply if we're asking about that device
    if (deviceId !== null && g.device_id === deviceId) return true;
    // device-scoped grant doesn't apply at org-level or for a different device
    // D1: BUT a device-scoped DENY still wins at org level? No:
    // "org-wide deny cannot be carved out by device-scoped allow" (D1)
    // Device-scoped grants only affect questions about that device.
    return false;
  });

  // D1: Check for any explicit deny first — deny wins regardless of scope
  for (const grant of applicableGrants) {
    if (grant.effect !== 'deny') continue;
    // Check all patterns in this grant
    const grantPerms = grant.patterns.flatMap(p => expandPattern(p, allPermissions));
    if (grantPerms.includes(permission)) {
      return { effect: 'deny', source: `grant:${grant.id}`, reason: 'explicit_deny' };
    }
  }

  // Check role baseline
  if (roleBaseline.has(permission)) {
    return { effect: 'allow', source: `role:${roleName}`, reason: null };
  }

  // Check allow grants
  for (const grant of applicableGrants) {
    if (grant.effect !== 'allow') continue;
    const grantPerms = grant.patterns.flatMap(p => expandPattern(p, allPermissions));
    if (grantPerms.includes(permission)) {
      return { effect: 'allow', source: `grant:${grant.id}`, reason: null };
    }
  }

  // D4: Absent means denied (implicit)
  return { effect: 'deny', source: null, reason: 'implicit' };
}

// Resolve one user's full permission set in one org at one scope.
// Returns { role, permissions: { [key]: { effect, source, reason } } }.
// deviceId === null → org-level view (only org-wide grants apply).
// deviceId !== null → exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const allPermissions = loadPermissions(db);
  const membership = db.prepare(
    "SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ? AND status != 'removed'"
  ).get(userId, orgId);

  // No membership in this org at all (cross-org, or user was removed)
  if (!membership) {
    const nonePerms = Object.fromEntries(
      allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'not_a_member' }])
    );
    return { role: null, permissions: nonePerms };
  }

  // Suspended members get total deny with reason 'suspended'
  if (membership.status === 'suspended') {
    const suspendedPerms = Object.fromEntries(
      allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'suspended' }])
    );
    return { role: membership.role, permissions: suspendedPerms };
  }

  const role = membership.role;
  const roleBaseline = loadRoleBaseline(db, role);
  const activeGrants = loadActiveGrants(db, userId, orgId, now);

  const permissions = {};
  for (const perm of allPermissions) {
    permissions[perm] = resolveOne(perm, roleBaseline, role, activeGrants, allPermissions, deviceId);
  }
  return { role, permissions };
}

// Batched: { role, byDevice: { [deviceId]: permissions } }
// Used by GET /devices to avoid N+1 queries.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const allPermissions = loadPermissions(db);
  const membership = db.prepare(
    'SELECT role FROM memberships WHERE user_id = ? AND org_id = ? AND status = ?'
  ).get(userId, orgId, 'active');

  if (!membership) {
    const emptySet = Object.fromEntries(
      allPermissions.map(p => [p, { effect: 'deny', source: null, reason: 'implicit' }])
    );
    return { role: null, byDevice: Object.fromEntries(deviceIds.map(id => [id, emptySet])) };
  }

  const role = membership.role;
  const roleBaseline = loadRoleBaseline(db, role);
  const activeGrants = loadActiveGrants(db, userId, orgId, now);

  const byDevice = {};
  for (const deviceId of deviceIds) {
    const perms = {};
    for (const perm of allPermissions) {
      perms[perm] = resolveOne(perm, roleBaseline, role, activeGrants, allPermissions, deviceId);
    }
    byDevice[deviceId] = perms;
  }

  return { role, byDevice };
}

// Returns true/false for one permission at one scope
export function can(db, ctx, permission, deviceId = null) {
  const { permissions } = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
    now: new Date(),
  });
  return permissions[permission]?.effect === 'allow';
}

// Throws 403 FORBIDDEN with reason code if caller lacks the permission.
export function assertCan(db, ctx, permission, deviceId = null) {
  const { permissions } = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
    now: new Date(),
  });
  const r = permissions[permission];
  if (!r || r.effect !== 'allow') {
    const reason = r?.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission';
    throw forbidden(`insufficient permission: ${permission}`, reason);
  }
}

// No privilege laundering: caller must hold every permission they are trying to grant,
// at the same or wider scope (D9).
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const allPermissions = loadPermissions(db);
  // Expand all patterns to concrete permissions
  const requested = patterns.flatMap(p => expandPattern(p, allPermissions));

  for (const perm of requested) {
    const scope = deviceId ?? null;
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: scope });
    if (permissions[perm]?.effect !== 'allow') {
      throw forbidden(`cannot grant ${perm}: you do not hold it at this scope`, 'missing_permission');
    }
  }

  // No self-grants (D9)
  // This is checked at the route level where we know the target userId.
}

// Compound check: session:start AND the mode-specific permission, both on the same device.
// Must distinguish which of the two was missing (for the error response).
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermissions = {
    view: 'device:view',
    control: 'device:control',
    terminal: 'device:terminal',
  };

  const modePerm = modePermissions[mode];
  if (!modePerm) throw forbidden(`unknown session mode: ${mode}`, 'missing_permission');

  const { permissions } = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
    now: new Date(),
  });

  // Check session:start first
  if (permissions['session:start']?.effect !== 'allow') {
    const reason = permissions['session:start']?.reason === 'explicit_deny'
      ? 'explicit_deny'
      : 'missing_permission';
    throw Object.assign(forbidden('cannot start session: session:start denied', reason), {
      missing: 'session:start',
    });
  }

  // Then check the mode permission (separate reason code: missing_device_permission)
  if (permissions[modePerm]?.effect !== 'allow') {
    const reason = permissions[modePerm]?.reason === 'explicit_deny'
      ? 'explicit_deny'
      : 'missing_device_permission';
    throw Object.assign(forbidden(`cannot start session: ${modePerm} denied`, reason), {
      missing: modePerm,
    });
  }
}
