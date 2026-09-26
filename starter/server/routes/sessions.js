// Session and audit routes
//
// POST   /v1/orgs/:org/sessions             session:start AND mode permission
// GET    /v1/orgs/:org/sessions             session:view
// GET    /v1/sessions/:id                   participant OR session:view
// DELETE /v1/sessions/:id                   own OR session:terminate
// GET    /v1/orgs/:org/users/:userId/effective   user:read OR self
// GET    /v1/orgs/:org/audit                audit:read

import { randomUUID } from 'node:crypto';
import { resolve, assertCan, assertCanStartSession, can } from '../permissions.js';
import { audit } from '../audit.js';
import { snapshotAuthority, sessionExpiry, endActiveSessions } from '../lifecycle.js';
import {
  send, badRequest, notFound, forbidden, conflict, deviceBusy
} from '../http.js';

function getSession(db, sessionId) {
  return db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
}

export function registerSessionRoutes(router, { db, secret }) {
  // POST /v1/orgs/:org/sessions — start session
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const { deviceId, mode } = ctx.body;
    if (!deviceId) throw badRequest('deviceId is required');
    if (!mode || !['view', 'control', 'terminal'].includes(mode)) {
      throw badRequest("mode must be 'view', 'control', or 'terminal'");
    }

    // Device must exist and belong to this org
    const device = db.prepare(
      'SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(deviceId, params.org);
    if (!device) throw notFound('device not found');

    // Check member is active (suspended → 403 before we go further)
    if (ctx.membership.status === 'suspended') throw forbidden('account suspended', 'suspended');

    // Compound permission check: session:start AND mode permission (D10)
    // assertCanStartSession throws with a `missing` property saying which one failed
    assertCanStartSession(db, ctx, mode, deviceId);

    // D10: control and terminal are exclusive per device (DB enforces via unique index)
    const sessionId = `ses_${randomUUID().replace(/-/g,'').slice(0,16)}`;
    const expiresAt = sessionExpiry(db, params.org);
    const authorizedBy = snapshotAuthority(db, {
      userId: ctx.userId, orgId: ctx.orgId, deviceId,
    });

    try {
      db.prepare(`
        INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
        VALUES (?, ?, ?, ?, ?, 'connecting', ?, ?)
      `).run(sessionId, params.org, ctx.userId, deviceId, mode, authorizedBy, expiresAt);

      // Transition to active immediately (in a real system this would be async)
      db.prepare("UPDATE sessions SET state = 'active' WHERE id = ?").run(sessionId);
    } catch (err) {
      // Unique constraint violation = DEVICE_BUSY
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE constraint'))) {
        const holder = db.prepare(
          "SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')"
        ).get(deviceId);
        const msg = holder ? `device busy: session ${holder.id} is active` : 'device already has an exclusive session';
        throw deviceBusy(msg);
      }
      throw err;
    }

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'session.start',
      targetType: 'session', targetId: sessionId, result: 'allow', requestId: ctx.requestId,
    });

    const session = getSession(db, sessionId);
    send(res, 201, { session });
  });

  // GET /v1/orgs/:org/sessions — list sessions
  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare(`
      SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC
    `).all(params.org);

    send(res, 200, { sessions });
  });

  // GET /v1/sessions/:id — participant OR session:view
  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const session = getSession(db, params.id);

    // Must belong to caller's org (structural isolation)
    if (!session || session.org_id !== ctx.orgId) throw notFound();

    // Visible to: participant OR session:view permission
    const isParticipant = session.user_id === ctx.userId;
    if (!isParticipant && !can(db, ctx, 'session:view')) throw notFound();

    send(res, 200, session);
  });

  // DELETE /v1/sessions/:id — end session
  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    const session = getSession(db, params.id);

    if (!session || session.org_id !== ctx.orgId) throw notFound();

    const isOwner = session.user_id === ctx.userId;
    const canTerminate = can(db, ctx, 'session:terminate');

    if (!isOwner && !canTerminate) throw notFound();

    if (session.state === 'ended') throw conflict('session is already ended');

    const reason = isOwner ? 'user_stopped' : 'admin_terminated';
    const now = new Date().toISOString();

    db.prepare("UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?")
      .run(reason, now, params.id);

    audit(db, {
      orgId: session.org_id, actorId: ctx.userId, action: 'session.end',
      targetType: 'session', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });

  // GET /v1/orgs/:org/users/:userId/effective — resolved permissions (user:read OR self)
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const isSelf = params.userId === ctx.userId;
    if (!isSelf) assertCan(db, ctx, 'user:read');

    // Target must be an active or suspended member
    const membership = db.prepare(
      "SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'"
    ).get(params.org, params.userId);
    if (!membership) throw notFound();

    const { permissions } = resolve(db, {
      userId: params.userId,
      orgId: params.org,
      deviceId: null,
      now: new Date(),
    });

    send(res, 200, { role: membership.role, permissions });
  });

  // GET /v1/orgs/:org/audit — audit log
  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'audit:read');

    const rawLimit = ctx.query?.get?.('limit');
    const rawOffset = ctx.query?.get?.('offset');

    const limit = rawLimit ? Number(rawLimit) : 100;
    const offset = rawOffset ? Number(rawOffset) : 0;

    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw badRequest('limit must be between 1 and 1000');
    if (!Number.isInteger(offset) || offset < 0) throw badRequest('offset must be 0 or greater');

    const events = db.prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?')
      .all(params.org, limit, offset);

    send(res, 200, { events });
  });
}
