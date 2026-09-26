// Members and invites routes
//
// GET    /v1/orgs/:org/members                        user:read
// PATCH  /v1/orgs/:org/members/:userId                user:role:update
// POST   /v1/orgs/:org/members/:userId/suspend        user:remove
// DELETE /v1/orgs/:org/members/:userId/suspend        user:remove (reinstate)
// DELETE /v1/orgs/:org/members/:userId                user:remove
// DELETE /v1/orgs/:org/members/me                     self (not last owner)
// POST   /v1/orgs/:org/invites                        user:invite
// GET    /v1/orgs/:org/invites                        user:invite
// DELETE /v1/orgs/:org/invites/:id                    user:invite
// GET    /v1/invites/:token                            public
// POST   /v1/invites/:token/accept                    public

import { randomUUID } from 'node:crypto';
import { newInviteToken, hashInviteToken, hashPassword } from '../auth.js';
import { assertCan } from '../permissions.js';
import { audit } from '../audit.js';
import {
  assertCanModify, assertNotLastOwner, assertRoleExists, endActiveSessions, roleRanks
} from '../lifecycle.js';
import {
  send, badRequest, notFound, forbidden, conflict, gone, selfRoleChange, lastOwner
} from '../http.js';

const INVITE_TTL_DAYS = 7;

function bumpPermVersion(db, orgId, userId) {
  db.prepare(`
    UPDATE memberships SET perm_version = perm_version + 1
    WHERE org_id = ? AND user_id = ?
  `).run(orgId, userId);
}

function getMembership(db, orgId, userId) {
  return db.prepare(`
    SELECT m.*, u.email, u.name as user_name
    FROM memberships m JOIN users u ON u.id = m.user_id
    WHERE m.org_id = ? AND m.user_id = ?
  `).get(orgId, userId);
}

export function registerMemberRoutes(router, { db, secret }) {
  // GET /v1/orgs/:org/members
  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:read');

    const members = db.prepare(`
      SELECT m.id, m.user_id, m.role, m.status, m.joined_at, m.created_at,
             u.email, u.name
      FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.status != 'removed'
      ORDER BY u.name
    `).all(params.org);

    send(res, 200, { members });
  });

  // PATCH /v1/orgs/:org/members/:userId — change role
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:role:update');

    const { role } = ctx.body;
    if (!role) throw badRequest('role is required');

    // Cannot change your own role (D8)
    if (params.userId === ctx.userId) throw selfRoleChange();

    const target = getMembership(db, params.org, params.userId);
    if (!target || target.status === 'removed') throw notFound();

    assertRoleExists(db, role);
    assertCanModify(db, ctx.role, target.role);       // can caller modify target's current role?
    assertCanModify(db, ctx.role, role);              // can caller assign the new role?
    assertNotLastOwner(db, params.org, params.userId); // can't demote last owner

    db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?')
        .run(role, params.org, params.userId);
      bumpPermVersion(db, params.org, params.userId);
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'member.role.update',
      targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { member: getMembership(db, params.org, params.userId) });
  });

  // POST /v1/orgs/:org/members/:userId/suspend
  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    const target = getMembership(db, params.org, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    if (target.status === 'suspended') throw conflict('member is already suspended');

    assertCanModify(db, ctx.role, target.role);
    assertNotLastOwner(db, params.org, params.userId);

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      bumpPermVersion(db, params.org, params.userId);
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'member.suspend',
      targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { member: getMembership(db, params.org, params.userId) });
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend — reinstate
  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    const target = getMembership(db, params.org, params.userId);
    if (!target || target.status === 'removed') throw notFound();
    if (target.status !== 'suspended') throw conflict('member is not suspended');

    assertCanModify(db, ctx.role, target.role);

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      bumpPermVersion(db, params.org, params.userId);
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'member.reinstate',
      targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 200, { member: getMembership(db, params.org, params.userId) });
  });

  // DELETE /v1/orgs/:org/members/me — self-leave
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();

    const target = getMembership(db, params.org, ctx.userId);
    if (!target || target.status === 'removed') throw notFound();

    assertNotLastOwner(db, params.org, ctx.userId);

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?")
        .run(params.org, ctx.userId);
      bumpPermVersion(db, params.org, ctx.userId);
      endActiveSessions(db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'member.leave',
      targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });

  // DELETE /v1/orgs/:org/members/:userId — remove member
  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:remove');

    if (params.userId === ctx.userId) throw selfRoleChange(); // use leave endpoint instead

    const target = getMembership(db, params.org, params.userId);
    if (!target || target.status === 'removed') throw notFound();

    assertCanModify(db, ctx.role, target.role);
    assertNotLastOwner(db, params.org, params.userId);

    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      bumpPermVersion(db, params.org, params.userId);
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
    })();

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'member.remove',
      targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });

  // POST /v1/orgs/:org/invites — create invite
  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || typeof email !== 'string') throw badRequest('email is required');
    if (!role || typeof role !== 'string') throw badRequest('role is required');

    const normalEmail = email.toLowerCase().trim();

    assertRoleExists(db, role);
    // Can only invite to a role caller can assign (D8 — rank check)
    try { assertCanModify(db, ctx.role, role); } catch {
      throw forbidden('you cannot assign this role', 'missing_permission');
    }

    // Check for existing active membership
    const existing = db.prepare(
      "SELECT status FROM memberships WHERE org_id = ? AND user_id = (SELECT id FROM users WHERE email = ?)"
    ).get(params.org, normalEmail);
    if (existing && existing.status === 'active') {
      throw conflict('user is already a member of this org');
    }

    // Check for live invite (DB unique index enforces this too, but better error)
    const liveInvite = db.prepare(
      'SELECT id FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL'
    ).get(params.org, normalEmail);
    if (liveInvite) throw conflict('a live invite already exists for this email');

    const rawToken = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const inviteId = `inv_${randomUUID().replace(/-/g,'').slice(0,16)}`;

    db.prepare(`
      INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(inviteId, params.org, normalEmail, role, tokenHash, ctx.userId, expiresAt);

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'invite.create',
      targetType: 'invite', targetId: inviteId, result: 'allow', requestId: ctx.requestId,
    });

    // Return the raw token exactly once — never store it, never log it
    send(res, 201, {
      invite: { id: inviteId, email: normalEmail, role, expiresAt, token: rawToken },
      inviteToken: rawToken,
    });
  });

  // GET /v1/orgs/:org/invites — list active invites
  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const invites = db.prepare(`
      SELECT id, email, role, expires_at, created_at
      FROM invites
      WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
      ORDER BY created_at DESC
    `).all(params.org);

    send(res, 200, { invites });
  });

  // DELETE /v1/orgs/:org/invites/:id — revoke invite
  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    if (params.org !== ctx.orgId) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const invite = db.prepare(
      'SELECT * FROM invites WHERE id = ? AND org_id = ?'
    ).get(params.id, params.org);

    if (!invite || invite.accepted_at || invite.revoked_at) throw notFound();

    db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), params.id);

    audit(db, {
      orgId: params.org, actorId: ctx.userId, action: 'invite.revoke',
      targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId,
    });

    send(res, 204);
  });

  // GET /v1/invites/:token — public, get invite info (no org data, no members)
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const tokenHash = hashInviteToken(params.token);
    const now = new Date().toISOString();

    const invite = db.prepare(`
      SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at,
             o.name as org_name
      FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?
    `).get(tokenHash);

    if (!invite) throw notFound('invite not found');
    if (invite.revoked_at) throw gone('invite has been revoked');
    if (invite.accepted_at) throw conflict('invite has already been accepted');
    if (invite.expires_at <= now) throw gone('invite has expired');

    send(res, 200, {
      orgName: invite.org_name,
      role: invite.role,
      email: invite.email,
      expiresAt: invite.expires_at,
    });
  });

  // POST /v1/invites/:token/accept — public, accept invite
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const tokenHash = hashInviteToken(params.token);
    const now = new Date().toISOString();

    const invite = db.prepare(`
      SELECT i.*, o.name as org_name
      FROM invites i JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?
    `).get(tokenHash);

    if (!invite) throw notFound('invite not found');
    if (invite.revoked_at) throw gone('invite has been revoked');
    if (invite.accepted_at) throw conflict('invite has already been accepted');
    if (invite.expires_at <= now) throw gone('invite has expired');

    const { name, password } = ctx.body;
    if (!password || typeof password !== 'string') throw badRequest('password is required');

    const accept = db.transaction(() => {
      // Upsert user: find by email, or create new
      let user = db.prepare('SELECT id FROM users WHERE email = ?').get(invite.email);

      if (!user) {
        if (!name || typeof name !== 'string') throw badRequest('name is required for new users');
        const userId = `usr_${randomUUID().replace(/-/g,'').slice(0,16)}`;
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(userId, invite.email, name.trim(), hashPassword(password));
        user = { id: userId };
      }

      // Upsert membership: invited → active
      const existing = db.prepare('SELECT id FROM memberships WHERE org_id = ? AND user_id = ?')
        .get(invite.org_id, user.id);

      if (existing) {
        db.prepare("UPDATE memberships SET status = 'active', role = ?, joined_at = ?, perm_version = perm_version + 1 WHERE id = ?")
          .run(invite.role, now, existing.id);
      } else {
        db.prepare(`
          INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
          VALUES (?, ?, ?, ?, 'active', ?, ?)
        `).run(`mbr_${randomUUID().replace(/-/g,'').slice(0,16)}`, invite.org_id, user.id, invite.role, invite.invited_by, now);
      }

      // Mark invite as accepted
      db.prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?')
        .run(now, user.id, invite.id);

      return user;
    });

    const user = accept();

    send(res, 200, {
      message: 'invite accepted',
      orgName: invite.org_name,
      role: invite.role,
    });
  });
}
