// Per-request context: turn a bearer token into an authenticated caller.
//
// Org isolation is STRUCTURAL: the caller can only address the org that is in
// their token's `org` claim. A request naming a different org returns 404 —
// not 403 — because confirming the org exists would itself be an info leak.
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries:
//   { userId, orgId, role, membership, claims }

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // 1. Extract the Bearer token from the Authorization header
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) throw unauthenticated('missing or invalid Authorization header');
    const token = authHeader.slice(7).trim();
    if (!token) throw unauthenticated('missing token');

    // 2. Verify the token — throws 401 on any failure
    const claims = verifyAccessToken(token, secret);

    // 3. Look up the membership for (userId, orgId) from the token
    //    The token's org claim is the ONLY org the caller may address (D18).
    //    We do NOT use params.org here because that would allow a request
    //    to a different org to get data before we check isolation.
    const userId = claims.sub;
    const orgId = claims.org;

    const membership = db.prepare(`
      SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ?
        AND o.deleted_at IS NULL
    `).get(userId, orgId);

    // Missing or removed membership → 401 (not a member at all, or membership removed)
    if (!membership || membership.status === 'removed') {
      throw unauthenticated('not a member of this org');
    }

    // 4. Freshness check — perm_version mismatch means a role/grant change happened
    //    after this token was issued; client must refresh.
    assertFresh(claims, membership);

    // 5. If this request's path has an :org param, verify it matches the token's org
    //    Structural isolation: return 404, never 403 (PERMISSIONS.md §5)
    if (params && params.org && params.org !== orgId) {
      throw notFound();
    }

    return { userId, orgId, role: claims.role, membership, claims };
  };
}
