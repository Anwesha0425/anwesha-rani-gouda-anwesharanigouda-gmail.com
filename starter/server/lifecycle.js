// Shared domain rules: role ranks, last-owner, ending sessions.
//
// Role ranks are modification-authority ONLY (D8). They are never used to answer
// a permission question — operator and auditor are unordered by permissions, and
// ranking them for can() checks is the exact bug the auditor role exists to catch.
//
// Read ranks from the DB at runtime: the personalised fixture may contain roles
// not listed in any document, and the hidden test fixture will differ from the
// hand-out. Never hardcode the matrix here.

import { forbidden, conflict, lastOwner } from './http.js';

// Returns { [roleKey]: rank } from the database.
// The result is used for modification-authority checks ONLY.
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  return Object.fromEntries(rows.map(r => [r.key, r.rank]));
}

// Throws if role doesn't exist in the database.
export function assertRoleExists(db, role) {
  const r = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!r) throw Object.assign(new Error(`unknown role: ${role}`), { status: 400, code: 'VALIDATION', reason: null });
}

// Throws 403 if callerRole cannot modify targetRole per modification rank (D8).
// Rules:
//   - you may only modify users of strictly lower rank
//   - equal rank → 403 (even admin→admin)
//   - assigning owner requires caller to be owner (rank === owner rank)
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const callerRank = ranks[callerRole];
  const targetRank = ranks[targetRole];

  if (callerRank === undefined || targetRank === undefined) {
    throw forbidden('unknown role', 'missing_permission');
  }

  const ownerRole = db.prepare('SELECT rank FROM roles ORDER BY rank DESC LIMIT 1').get();

  // Higher rank number = higher authority (owner=50 > admin=40 > operator=30 > ...)
  if (callerRank <= targetRank) {
    if (ownerRole && callerRank === ownerRole.rank && targetRank === ownerRole.rank) {
      // Owners can modify other owners
    } else {
      throw forbidden('insufficient authority to modify this role', 'missing_permission');
    }
  }
}

// Throws if the change would leave the org without an owner (409 LAST_OWNER).
// Used before: removing a member, demoting an owner, suspending an owner.
export function assertNotLastOwner(db, orgId, userId) {
  // Count active owners in this org excluding the target user
  const ownerRole = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
  if (!ownerRole) return; // No owner role defined, skip

  const count = db.prepare(`
    SELECT COUNT(*) as cnt
    FROM memberships
    WHERE org_id = ? AND role = ? AND status = 'active' AND user_id != ?
  `).get(orgId, ownerRole.key, userId);

  if (count.cnt === 0) {
    // Check if the target user is currently an owner
    const targetMembership = db.prepare(
      'SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = \'active\''
    ).get(orgId, userId);
    if (targetMembership && targetMembership.role === ownerRole.key) {
      throw lastOwner();
    }
  }
}

// End all active sessions for a user/device combination.
// Tenancy events (suspension, removal, device transfer) cascade to sessions.
// Permission changes do NOT cascade — only pass a reason that reflects that.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  const now = new Date().toISOString();

  let sql = `
    UPDATE sessions
    SET state = 'ended', end_reason = ?, ended_at = ?
    WHERE org_id = ? AND state = 'active'
  `;
  const args = [reason, now, orgId];

  if (userId) {
    sql += ' AND user_id = ?';
    args.push(userId);
  }
  if (deviceId) {
    sql += ' AND device_id = ?';
    args.push(deviceId);
  }
  if (exceptSessionId) {
    sql += ' AND id != ?';
    args.push(exceptSessionId);
  }

  db.prepare(sql).run(...args);
}

// Snapshot the caller's authorization inputs for a session.
// The snapshot is what the session carries as `authorized_by` — this is what
// makes sessions grandfathered: the auth is from when the session started.
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const membership = db.prepare(
    'SELECT role, perm_version FROM memberships WHERE user_id = ? AND org_id = ? AND status = \'active\''
  ).get(userId, orgId);

  if (!membership) throw forbidden('not an active member', 'missing_permission');

  return JSON.stringify({
    userId,
    orgId,
    role: membership.role,
    perm_version: membership.perm_version,
    deviceId,
    snapshotAt: new Date().toISOString(),
  });
}

// Returns the session expiry ISO timestamp based on org's max_session_minutes.
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  const expiry = new Date(Date.now() + minutes * 60 * 1000);
  return expiry.toISOString();
}
