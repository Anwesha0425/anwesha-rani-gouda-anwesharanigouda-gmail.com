// Org routes: list, create, update, delete
//
// GET    /v1/orgs                   authenticated — list caller's orgs
// POST   /v1/orgs                   authenticated — create org (caller becomes owner)
// PATCH  /v1/orgs/:org              org:update
// DELETE /v1/orgs/:org              org:delete

import { randomUUID } from 'node:crypto';
import { resolve, assertCan } from '../permissions.js';
import { audit } from '../audit.js';
import { send, badRequest, notFound, conflict } from '../http.js';

const THEMES = ['cobalt', 'crimson', 'forest', 'amber', 'violet', 'slate'];

function getOrg(db, orgId) {
  return db.prepare('SELECT * FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
}

export function registerOrgRoutes(router, { db, secret }) {
  // GET /v1/orgs — list caller's orgs (all memberships)
  router.get('/v1/orgs', async (ctx, params, res) => {
    const orgs = db.prepare(`
      SELECT o.id, o.name, o.theme, o.created_at, m.role, m.status
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
        AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(ctx.userId);

    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create org; caller becomes owner
  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name, theme } = ctx.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      throw badRequest('name is required');
    }
    if (name.trim().length > 100) throw badRequest('name too long (max 100)');
    if (theme && !THEMES.includes(theme)) throw badRequest(`theme must be one of: ${THEMES.join(', ')}`);

    // Find the owner role (highest rank = highest authority)
    const ownerRole = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
    if (!ownerRole) throw badRequest('no owner role defined');

    const orgId = `org_${randomUUID().replace(/-/g,'').slice(0,16)}`;
    const membId = `mbr_${randomUUID().replace(/-/g,'').slice(0,16)}`;
    const now = new Date().toISOString();

    const create = db.transaction(() => {
      db.prepare(`
        INSERT INTO organizations (id, name, theme, created_at)
        VALUES (?, ?, ?, ?)
      `).run(orgId, name.trim(), theme ?? THEMES[0], now);

      db.prepare(`
        INSERT INTO memberships (id, org_id, user_id, role, status, joined_at, created_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?)
      `).run(membId, orgId, ctx.userId, ownerRole.key, now, now);
    });

    create();

    const org = getOrg(db, orgId);
    audit(db, {
      orgId,
      actorId: ctx.userId,
      action: 'org.create',
      targetType: 'org',
      targetId: orgId,
      result: 'allow',
      reasonCode: null,
      requestId: ctx.requestId,
    });

    const responseObj = { id: org.id, name: org.name, theme: org.theme, role: ownerRole.key };
    send(res, 201, { ...responseObj, org: responseObj });
  });

  // PATCH /v1/orgs/:org — update org (requires org:update)
  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    const org = getOrg(db, params.org);
    if (!org || org.id !== ctx.orgId) throw notFound();

    assertCan(db, ctx, 'org:update');

    const { name, theme, max_session_minutes } = ctx.body;
    const updates = {};
    if (name !== undefined) {
      if (typeof name !== 'string' || name.trim().length === 0) throw badRequest('name must be non-empty');
      if (name.trim().length > 100) throw badRequest('name too long');
      updates.name = name.trim();
    }
    if (theme !== undefined) {
      if (!THEMES.includes(theme)) throw badRequest(`theme must be one of: ${THEMES.join(', ')}`);
      updates.theme = theme;
    }
    if (max_session_minutes !== undefined) {
      if (typeof max_session_minutes !== 'number' || max_session_minutes < 1) {
        throw badRequest('max_session_minutes must be a positive number');
      }
      updates.max_session_minutes = max_session_minutes;
    }

    if (Object.keys(updates).length === 0) throw badRequest('no fields to update');

    const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    db.prepare(`UPDATE organizations SET ${setClauses} WHERE id = ?`).run(...Object.values(updates), org.id);

    audit(db, {
      orgId: org.id, actorId: ctx.userId, action: 'org.update',
      targetType: 'org', targetId: org.id, result: 'allow', requestId: ctx.requestId,
    });

    const updated = getOrg(db, org.id);
    send(res, 200, { org: updated });
  });

  // DELETE /v1/orgs/:org — soft-delete org (requires org:delete)
  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    const org = getOrg(db, params.org);
    if (!org || org.id !== ctx.orgId) throw notFound();

    assertCan(db, ctx, 'org:delete');

    const now = new Date().toISOString();
    db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(now, org.id);

    audit(db, {
      orgId: org.id, actorId: ctx.userId, action: 'org.delete',
      targetType: 'org', targetId: org.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });
}
