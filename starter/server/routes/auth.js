// Auth routes: login, refresh, token (org switch), me
//
// POST /v1/auth/login    — email + password → access token (memory) + refresh cookie
// POST /v1/auth/refresh  — rotate refresh cookie → new access token
// POST /v1/auth/token    — { orgId } → new access token for that org
// GET  /v1/auth/me       — caller info + org-level resolved permissions

import { randomUUID } from 'node:crypto';
import {
  issueAccessToken, hashPassword, verifyPassword,
  newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS,
} from '../auth.js';
import { authenticate, } from '../context.js';
import { resolve } from '../permissions.js';
import { send, badRequest, unauthenticated, forbidden, notFound } from '../http.js';

const REFRESH_COOKIE_NAME = 'remoteops_refresh';
const REFRESH_COOKIE_OPTIONS = `; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`;

function setRefreshCookie(res, token) {
  res.setHeader('Set-Cookie', `${REFRESH_COOKIE_NAME}=${token}${REFRESH_COOKIE_OPTIONS}`);
}

function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', `${REFRESH_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Max-Age=0`);
}

function parseCookies(req) {
  const raw = req.headers['cookie'] ?? '';
  return Object.fromEntries(
    raw.split(';').map(s => s.trim().split('=').map(decodeURIComponent))
  );
}

export function registerAuthRoutes(router, { db, secret }) {
  // POST /v1/auth/login
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password } = ctx.body;
    if (!email || typeof email !== 'string') throw badRequest('email is required');
    if (!password || typeof password !== 'string') throw badRequest('password is required');

    // Look up user — same error for wrong email and wrong password (D enumeration oracle)
    const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid credentials');
    }

    // Find the user's memberships to get their orgs
    const memberships = db.prepare(`
      SELECT m.org_id, m.role, m.status, m.perm_version, o.name, o.theme
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
        AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(user.id);

    if (memberships.length === 0) throw unauthenticated('no active memberships');

    // Default org: first active membership (not suspended)
    const activeMembership = memberships.find(m => m.status === 'active') ?? memberships[0];
    if (activeMembership.status === 'suspended') throw forbidden('account suspended', 'suspended');

    // Issue tokens for the default org
    const accessToken = issueAccessToken({
      userId: user.id,
      orgId: activeMembership.org_id,
      role: activeMembership.role,
      permVersion: activeMembership.perm_version,
    }, secret);

    const rawRefresh = newRefreshToken();
    const tokenHash = hashRefreshToken(rawRefresh);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
    const familyId = randomUUID();

    db.prepare(`
      INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(`rtk_${randomUUID().replace(/-/g,'').slice(0,16)}`, user.id, tokenHash, familyId, expiresAt);

    setRefreshCookie(res, rawRefresh);
    send(res, 200, {
      token: accessToken,
      accessToken,
      role: activeMembership.role,
      orgs: memberships,
      user: { id: user.id, email: user.email },
      org: {
        id: activeMembership.org_id,
        name: activeMembership.name,
        theme: activeMembership.theme,
      },
      permissions: resolve(db, { userId: user.id, orgId: activeMembership.org_id }).permissions,
    });
  });

  // POST /v1/auth/refresh
  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    const cookies = parseCookies(ctx.req);
    const rawRefresh = cookies[REFRESH_COOKIE_NAME];
    if (!rawRefresh) throw unauthenticated('missing refresh token');

    const tokenHash = hashRefreshToken(rawRefresh);
    const now = new Date().toISOString();

    const stored = db.prepare(`
      SELECT rt.id, rt.user_id, rt.family_id, rt.revoked_at, rt.expires_at
      FROM refresh_tokens rt
      WHERE rt.token_hash = ?
    `).get(tokenHash);

    // Token reuse detection: if the token was already used (rotated), revoke the whole family
    if (stored && stored.revoked_at !== null) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(now, stored.family_id);
      clearRefreshCookie(res);
      throw unauthenticated('refresh token reuse detected; please log in again');
    }

    if (!stored || stored.expires_at <= now) {
      clearRefreshCookie(res);
      throw unauthenticated('invalid or expired refresh token');
    }

    // Revoke the old token (rotation)
    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(now, stored.id);

    // Get user's current default membership
    const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(stored.user_id);
    const memberships = db.prepare(`
      SELECT m.org_id, m.role, m.status, m.perm_version, o.name, o.theme
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active'
        AND o.deleted_at IS NULL
      ORDER BY o.name
      LIMIT 1
    `).get(stored.user_id);

    if (!memberships) throw unauthenticated('no active memberships');

    const accessToken = issueAccessToken({
      userId: user.id,
      orgId: memberships.org_id,
      role: memberships.role,
      permVersion: memberships.perm_version,
    }, secret);

    // Issue new refresh token
    const rawNew = newRefreshToken();
    const newHash = hashRefreshToken(rawNew);
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();

    db.prepare(`
      INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(`rtk_${randomUUID().replace(/-/g,'').slice(0,16)}`, user.id, newHash, stored.family_id, expiresAt);

    setRefreshCookie(res, rawNew);
    send(res, 200, {
      token: accessToken,
      accessToken,
      role: memberships.role,
      user: { id: user.id, email: user.email },
      org: {
        id: memberships.org_id,
        name: memberships.name,
        theme: memberships.theme,
      },
      permissions: resolve(db, { userId: user.id, orgId: memberships.org_id }).permissions,
    });
  });

  // POST /v1/auth/token — switch org
  // Requires: active membership in orgId
  router.post('/v1/auth/token', async (ctx, params, res) => {
    // ctx already has userId from the bearer token (handled in index.js)
    const { orgId } = ctx.body;
    if (!orgId || typeof orgId !== 'string') throw badRequest('orgId is required');

    // Verify the caller has an active membership in the requested org
    const membership = db.prepare(`
      SELECT m.role, m.status, m.perm_version, o.name, o.theme
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ?
        AND o.deleted_at IS NULL
    `).get(ctx.userId, orgId);

    if (!membership || membership.status === 'removed') throw notFound();
    if (membership.status === 'suspended') throw forbidden('account suspended in this org', 'suspended');
    if (membership.status !== 'active') throw unauthenticated('not an active member');

    const accessToken = issueAccessToken({
      userId: ctx.userId,
      orgId,
      role: membership.role,
      permVersion: membership.perm_version,
    }, secret);

    send(res, 200, {
      token: accessToken,
      accessToken,
      role: membership.role,
      org: {
        id: orgId,
        name: membership.name,
        theme: membership.theme,
      },
      permissions: resolve(db, { userId: ctx.userId, orgId }).permissions,
    });
  });

  // GET /v1/auth/me — caller info + org-level resolved permissions
  router.get('/v1/auth/me', async (ctx, params, res) => {
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(ctx.userId);

    // Get all orgs the caller belongs to
    const orgs = db.prepare(`
      SELECT m.org_id as id, o.name, o.theme, m.role, m.status
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
        AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(ctx.userId);

    // Org-level permissions for the current org
    const { permissions } = resolve(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceId: null,
      now: new Date(),
    });


    const currentOrg = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(ctx.orgId);

    send(res, 200, {
      user: { id: user.id, email: user.email, name: user.name },
      role: ctx.role,
      org: {
        id: ctx.orgId,
        name: currentOrg?.name,
        theme: currentOrg?.theme,
      },
      orgs,
      permissions,
    });
  });
}
