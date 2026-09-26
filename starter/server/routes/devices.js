// Device and grant routes
//
// GET    /v1/orgs/:org/devices                         device:list
// GET    /v1/orgs/:org/devices/:id                     device:view
// POST   /v1/orgs/:org/devices                         device:provision
// PATCH  /v1/orgs/:org/devices/:id                     device:update
// DELETE /v1/orgs/:org/devices/:id                     device:provision
// POST   /v1/orgs/:org/devices/:id/transfer            device:provision in BOTH orgs
//
// POST   /v1/orgs/:org/grants                          grant:create
// GET    /v1/orgs/:org/grants                          user:read
// DELETE /v1/orgs/:org/grants/:id                      grant:revoke

import { randomUUID } from 'node:crypto';
import { resolve, resolveDevices, assertCan, assertMayGrant, can } from '../permissions.js';
import { audit } from '../audit.js';
import { endActiveSessions } from '../lifecycle.js';
import {
  send, badRequest, notFound, forbidden, conflict, normalizeTs
} from '../http.js';

const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

function getDevice(db, orgId, deviceId) {
  return db.prepare(
    'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
  ).get(deviceId, orgId);
}

function bumpPermVersion(db, orgId, userId) {
  db.prepare(
    'UPDATE memberships SET perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?'
  ).run(orgId, userId);
}

export function registerDeviceRoutes(router, { db, secret }) {
  // GET /v1/orgs/:org/devices — list + per-device permissions for caller (avoids N+1)
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'device:list');

    const allDevices = db.prepare(`
      SELECT id, name, kind, online, created_at
      FROM devices WHERE org_id = ? AND deleted_at IS NULL
      ORDER BY name
    `).all(params.org);

    const deviceIds = allDevices.map(d => d.id);
    const { byDevice } = resolveDevices(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceIds,
      now: new Date(),
    });

    // Filter out devices the caller cannot view (device:view deny = row not in response)
    const devices = allDevices
      .filter(d => byDevice[d.id]?.['device:view']?.effect === 'allow')
      .map(d => ({ ...d, permissions: byDevice[d.id] }));

    send(res, 200, { devices });
  });

  // GET /v1/orgs/:org/devices/:id
  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();

    // Check device:view before returning — invisible → 404
    if (!can(db, ctx, 'device:view', params.id)) throw notFound();

    const { permissions } = resolve(db, {
      userId: ctx.userId, orgId: ctx.orgId, deviceId: params.id, now: new Date(),
    });

    send(res, 200, { device: { ...device, permissions } });
  });

  // POST /v1/orgs/:org/devices — provision device
  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'device:provision');

    const { name, kind } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
    if (!kind || !DEVICE_KINDS.includes(kind)) throw badRequest(`kind must be one of: ${DEVICE_KINDS.join(', ')}`);

    const deviceId = `dev_${randomUUID().replace(/-/g,'').slice(0,16)}`;

    db.prepare('INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)')
      .run(deviceId, params.org, name.trim(), kind);

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'device.provision',
      targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId,
    });

    const device = getDevice(db, params.org, deviceId);
    send(res, 201, { device });
  });

  // PATCH /v1/orgs/:org/devices/:id
  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();
    if (!can(db, ctx, 'device:view', params.id)) throw notFound();

    assertCan(db, ctx, 'device:update', params.id);

    const { name, online } = ctx.body;
    const updates = {};
    if (name !== undefined) {
      if (typeof name !== 'string' || !name.trim()) throw badRequest('name must be non-empty');
      updates.name = name.trim();
    }
    if (online !== undefined) {
      if (typeof online !== 'boolean') throw badRequest('online must be a boolean');
      updates.online = online ? 1 : 0;
    }
    if (Object.keys(updates).length === 0) throw badRequest('no fields to update');

    const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE devices SET ${setClauses} WHERE id = ?`).run(...Object.values(updates), params.id);

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'device.update',
      targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    const updated = getDevice(db, params.org, params.id);
    send(res, 200, { device: updated });
  });

  // DELETE /v1/orgs/:org/devices/:id — soft-delete
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();
    if (!can(db, ctx, 'device:view', params.id)) throw notFound();

    assertCan(db, ctx, 'device:provision', params.id);

    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?')
        .run(new Date().toISOString(), params.id);
      endActiveSessions(db, { orgId: params.org, deviceId: params.id, reason: 'device_transferred' });
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'device.delete',
      targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });

  // POST /v1/orgs/:org/devices/:id/transfer — transfer device to another org
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();
    if (!can(db, ctx, 'device:view', params.id)) throw notFound();

    assertCan(db, ctx, 'device:provision', params.id);

    const { toOrgId } = ctx.body;
    if (!toOrgId) throw badRequest('toOrgId is required');

    // Must have device:provision in the destination org too
    const destMembership = db.prepare(
      "SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'"
    ).get(toOrgId, ctx.userId);
    if (!destMembership) throw forbidden('not a member of destination org', 'missing_permission');

    const destCtx = { ...ctx, orgId: toOrgId, role: destMembership.role };
    assertCan(db, destCtx, 'device:provision');

    db.transaction(() => {
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(toOrgId, params.id);
      endActiveSessions(db, { orgId: params.org, deviceId: params.id, reason: 'device_transferred' });
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'device.transfer',
      targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { device: { ...device, org_id: toOrgId } });
  });

  // POST /v1/orgs/:org/grants — create grant
  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'grant:create');

    const { userId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body;

    if (!userId) throw badRequest('userId is required');
    if (!effect || !['allow', 'deny'].includes(effect)) throw badRequest("effect must be 'allow' or 'deny'");
    if (!permissions || !Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }

    // No self-grants (D9)
    if (userId === ctx.userId) throw forbidden('you cannot create a grant for yourself', 'missing_permission');

    // Target must be an active member of this org
    const target = db.prepare(
      "SELECT id FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'"
    ).get(params.org, userId);
    if (!target) throw notFound('user is not an active member of this org');

    // If deviceId specified, must belong to this org
    if (deviceId) {
      const device = getDevice(db, params.org, deviceId);
      if (!device) throw notFound('device not found in this org');
    }

    // Validate and normalize timestamps
    const startsAtIso = normalizeTs(startsAt, 'startsAt');
    const expiresAtIso = normalizeTs(expiresAt, 'expiresAt');

    const now = new Date().toISOString();
    if (expiresAtIso && expiresAtIso <= now) {
      throw Object.assign(new Error('expiresAt is already in the past'), { status: 400, code: 'GRANT_EXPIRED', reason: null });
    }

    // No privilege laundering: caller must hold every permission they're granting (D9)
    // expand patterns and check each
    assertMayGrant(db, ctx, permissions, deviceId ?? null);

    const grantId = `grt_${randomUUID().replace(/-/g,'').slice(0,16)}`;

    try {
      db.transaction(() => {
        db.prepare(`
          INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(grantId, params.org, userId, deviceId ?? null, effect, startsAtIso, expiresAtIso, ctx.userId);

        const stmt = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
        for (const perm of permissions) {
          stmt.run(grantId, perm);
        }

        bumpPermVersion(db, params.org, userId);
      })();
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY') {
        throw badRequest('unknown permission', 'unknown_permission');
      }
      throw err;
    }

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'grant.create',
      targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId,
    });

    const grant = db.prepare('SELECT * FROM grants WHERE id = ?').get(grantId);
    send(res, 201, { grant: { ...grant, permissions } });
  });

  // GET /v1/orgs/:org/grants
  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:read');

    const grants = db.prepare(`
      SELECT g.*, GROUP_CONCAT(gp.permission, ',') as permission_list
      FROM grants g
      LEFT JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.org_id = ? AND g.revoked_at IS NULL
      GROUP BY g.id
      ORDER BY g.created_at DESC
    `).all(params.org);

    const formatted = grants.map(g => ({
      ...g,
      permissions: g.permission_list ? g.permission_list.split(',') : [],
      permission_list: undefined,
    }));

    send(res, 200, { grants: formatted });
  });

  // DELETE /v1/orgs/:org/grants/:id — revoke grant
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(
      'SELECT * FROM grants WHERE id = ? AND org_id = ?'
    ).get(params.id, params.org);

    if (!grant || grant.revoked_at !== null) throw notFound();

    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?')
        .run(new Date().toISOString(), params.id);
      bumpPermVersion(db, params.org, grant.user_id);
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'grant.revoke',
      targetType: 'grant', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });
}
