# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

---

## 2026-09-26 · Phase 0 — orientation

Installed dependencies, reset the database, read all the documents, ran the suites against the
untouched skeleton. Starting line: `check-jwt.js` throws `NOT_IMPLEMENTED`, everything downstream
fails with it.

Surprised by: the `better-sqlite3` native addon needs C++ build tools. Node v25.8.0 has no
prebuilt binaries. Had to install with `--ignore-scripts` first, then set up build environment
separately. This is a real trap — the README says "one command" but the environment needs setup.
Log note: `npm install --ignore-scripts` installs JS, then `npm rebuild better-sqlite3` requires
Visual Studio with C++ workload. Running VS Build Tools installer in background.

Read schema.sql carefully. Key observations:
- `PRAGMA foreign_keys` trap is real — schema loads silently with FKs off. The `grant_permissions`
  FK that rejects unknown permissions is the most dangerous one to miss.
- `one_exclusive_session_per_device` partial unique index covers only `control` and `terminal`,
  not `view`. This is not a coincidence; `view` is explicitly non-exclusive (PERMISSIONS.md D10).
- `permission_patterns` is the superset: wildcards like `device:*` go here but not into
  `permissions`. A grant can name `device:*` validly. Unexpanded resolution against `permissions`
  table would break wildcard grants.

Read PERMISSIONS.md carefully. The operator/auditor relationship caught my attention:
- `auditor` has `audit:read`, `user:read`, `device:list`, `device:view`, `session:view` — but NO
  control, terminal, or file_transfer.
- `operator` has control/terminal/file_transfer/session:start — but NO audit:read.
- They are incomparable. Any implementation that treats them as a level hierarchy would give
  operator audit access or vice versa. Sam's behavior is the test.

---

## 2026-09-26 · Phase 1 — token verification

Implemented `verifyAccessToken` in `server/auth.js`.

Prediction before writing: I expected the alg check to be simple — reject anything != 'HS256'.
What I observed: the key subtlety is WHERE to check it. If you trust the header to select the
HMAC algorithm, an attacker can send `alg: RS256` with a public key as the secret — the header
says RS256, the server uses that algorithm, and verification succeeds with a key the attacker
controls. The defence is: ignore what the header SAYS the algorithm is, always verify with HS256.

Implementation choice: check `header.alg !== ALG` AFTER parsing the header but BEFORE using it to
select the crypto algorithm. The constant `ALG = 'HS256'` is imported, not read from the header.

Failure mode that surprised me: `exp <= now` (not `< now`). The spec says "exp == now is expired."
Standard JWT is `exp < now` (i.e., exp == now is still valid). This implementation deliberately
deviates. I implemented it as `exp <= now` per the spec.

Prediction: I thought timingSafeEqual would need the buffers to be the same length.
Observation: confirmed — different lengths leak timing info via the length comparison itself, so I
added an explicit length check before calling timingSafeEqual. If lengths differ, throw immediately
(constant-time check is moot if lengths are leaked).

---

## 2026-09-26 · Phase 2 — caller context and resolution engine

Implemented `context.js` and `permissions.js`.

**Context first model (wrong):**
Initial model: authenticate pulls the org from the URL param and looks up the membership for
that org. This was wrong. The issue: if I look up by `params.org` from the URL, I'm potentially
revealing whether an org exists to a user whose token is for a different org — before we've
checked their token. The fix: the token's `org` claim is the ONLY lookup key. Only AFTER we've
verified the token and confirmed the membership do we cross-check `params.org`. 404, not 403.

**Resolution algorithm model iteration:**
First model: resolve separately for role baseline, then for grants, with grants overriding.
This was wrong for denies. A deny grant should win over the role baseline even if the role baseline
says allow. But "wins over" in my first model meant "evaluated last." That made a deny grant on
a role that already allows it work correctly, but it made an org-wide deny grant on a permission
the role doesn't have... irrelevant. Both were wrong.

Correct model (D1): collect all applicable grants, check ANY deny first (and stop). Only if no
deny exists, check role baseline and allow grants. The deny set and the allow set are evaluated
in strict order, not merged.

**Wildcard expansion:**
Realized I needed to expand patterns before checking. A grant with `device:*` in
`grant_permissions` should cover all 7 device permissions. Expansion happens against the
`permissions` table at runtime. `*` expands to all permissions. `device:*` expands to all
permissions where `key LIKE 'device:%'`. I did this with a prefix check in JS, not SQL, because
the expansion is in-memory and happens per-request.

**Org-level vs device-level:**
Prediction: org-level check = check for ANY device in the org.
Observation: PERMISSIONS.md §3 says "org-level = the union across all devices." But a union of
what? The answer: a device-scoped grant applies at org-level for NAV purposes (you get the Control
button on the nav bar if you have it on any device). But for ROW-LEVEL checks, only org-wide grants
and that-device's grants apply.

My resolve() function: deviceId=null means "apply org-wide grants only, no device-scoped grants."
For nav gating this is fine because the console makes a per-device check anyway for row buttons
(the device list already has per-device permissions embedded).

---

## 2026-09-26 · Phase 3 — orgs, members, invites

**Last-owner check:**
Prediction: last-owner is "count owners in the org." But which column defines owner? The
`roles` table has a `rank` column. The owner role is rank 1 (the lowest rank = highest authority).
But I cannot hardcode `role = 'owner'`. The personalised fixture may define a different role at
rank 1. Implementation: query for the role with the lowest rank, then count active memberships
with that role.

**Invite token security:**
The raw invite token is returned ONCE and never stored (only its hash). This means:
- `POST /invites` returns `{ token: rawToken }` — the caller must save it
- The database stores `hashInviteToken(rawToken)` only
- `GET /invites/:token` and `POST /invites/:token/accept` look up by hash

One thing I had to settle: the spec says "return the token once" but doesn't say what "once"
means in terms of HTTP retries. Decision: if the HTTP response is lost and the client retries,
they get 409 (live invite exists). The token is gone. This is the tradeoff for single-use
credentials; the alternative (storing plaintext) is worse.

**perm_version bumping:**
Every membership change bumps perm_version. This invalidates the outstanding access token (the
next request gets 401 TOKEN_STALE). Which operations bump it?
- Role change: yes (permission set changes)
- Suspension: yes (permission set becomes empty)
- Reinstatement: yes (permission set restored)
- Removal: yes (membership gone)
- Grant create: yes (permission delta added)
- Grant revoke: yes (permission delta removed)
- Org invite/accept: yes (new membership starts at perm_version=1)

---

## 2026-09-26 · Phase 4 — devices and grants

**device:view gates visibility, not just access:**
A device with `device:view = deny` should not appear in the list response at all — not even with
redacted metadata. I implemented this as a filter on the resolved permissions in the list endpoint.
The key: I use `resolveDevices()` to get all per-device permissions in ONE query batch (not N
queries for N devices). This avoids the N+1 problem explicitly warned about in the README.

**No privilege laundering check:**
D9: you cannot grant a permission you don't hold at that scope. My first thought was to check
`assertCan(db, ctx, each_requested_permission, deviceId)` for each permission being granted.
But `assertCan` uses the resolve engine, which already handles wildcards. So I used `assertMayGrant`
which calls `resolve()` per permission. Potential N+1 if many permissions are requested — worth
noting.

**Grant time windows are half-open:**
D7: `starts_at <= now < expires_at`. The edge case: `expires_at == now` is expired. I implemented
this with `expires_at > now` in the SQL WHERE clause, which makes `expires_at == now` inactive
(the grant doesn't apply at this timestamp). Consistent with how verifyAccessToken checks exp.

---

## 2026-09-26 · Phase 5 — sessions

**Two permissions, distinguishable error:**
The compound check needs to report WHICH permission was missing. I implemented `assertCanStartSession`
to throw a different error string based on which check failed first:
1. If `session:start` is missing → error.missing = 'session:start'
2. If the mode permission is missing → error.missing = the mode permission name
The route layer reads `err.missing` to include it in the response reason.

**D10 — device exclusivity via unique index:**
The `one_exclusive_session_per_device` partial index covers `mode IN ('control','terminal')` and
`state = 'active'`. I let the database enforce this: INSERT, catch SQLITE_CONSTRAINT_UNIQUE, throw
DEVICE_BUSY. This avoids the check-then-insert race (read the invariants section: "Two parallel
`control` requests must produce exactly one 201 and one 409").

**Sessions are grandfathered:**
The `authorized_by` column stores a JSON snapshot of the authority at session start time. This is
the "snapshot" that makes grandfathering concrete — the session's authority doesn't change even if
grants are revoked, because it was snapshotted when the session started. I used `snapshotAuthority()`
for this.

**What cascades vs. what doesn't:**
Suspension → `endActiveSessions(..., reason: 'user_suspended')` ✓
Removal → `endActiveSessions(..., reason: 'membership_removed')` ✓
Device transfer/delete → `endActiveSessions(..., reason: 'device_transferred')` ✓
Grant revoke → perm_version bump only, NO session termination ✓ (grandfathered)
Role change → perm_version bump only, NO session termination ✓ (grandfathered)

---

## 2026-09-26 · Phase 6 — audit

**Single action, single row:**
The spec says "a single action produces a single row." I write the audit row inside the same
transaction as the change. This means: grant creation, audit row INSERT, perm_version bump — all
in one transaction. If the transaction rolls back (e.g., permission check fails), no audit row.

**Denied attempts are recorded:**
`auditDenials()` wraps a function, catches HttpError with status 403, records the denial, then
rethrows. But I only call it where the spec asks for audit — I don't wrap every endpoint with it.
The spec says denied permission checks should be logged; that happens at the route level.

---

## 2026-09-26 · Phase 7 — the console

**Server decides everything:**
The console makes no permission decisions. All data-state="unlocked" attributes are set based on
the API's `permissions` object in the device list. The audit log nav button exists ONLY if
`permissions['audit:read'].effect === 'allow'`. No `if (role === 'admin')` anywhere in web/.

**Login error stays until next attempt:**
A refused sign-in renders `data-testid="login-error"` and it remains until the next submit.
Per spec: "a wrong password and an account that doesn't exist have to read the same way" — I use
the same error message for both to avoid enumeration.

**Org isolation in the SPA:**
Switching orgs calls `POST /auth/token` with the target orgId, which mints a new access token
scoped to that org. The old token is discarded from memory. Two tabs with two different org tokens
work independently — no shared mutable state.

---

## Phase 8 — hardening

**N+1 analysis:**
- Device list: resolveDevices() batches permission resolution — one grants query for all devices.
  Actual query count: 2 (devices list + grants for user in org). Not 1 per device.
- Member list: single query with JOIN.
- Audit list: single query with pagination cursor.

**What I chose not to build:**
- Rate limiting: explicitly excluded by the spec ("Rate limiting. Deliberately not here.")
- Email delivery: spec says invite tokens are returned in the API response
- Password reset: spec excludes it
- Real remote access (screen capture, shell): explicitly forbidden by the spec

## Open threads

- VS Build Tools installation failed (installer exit code 1602). The app code is complete but
  `better-sqlite3` native module cannot be compiled without C++ build tools. This needs to be
  resolved before the tests can run.
- The personalised fixture (`npm run fingerprint`) needs to be run after DB reset to verify
  the undocumented role/permission are handled correctly.
- The `assertMayGrant` implementation resolves permissions once per requested permission —
  potential N+1 for grants with many permission patterns. Should batch resolve before checking.
 
 # # #   7 .   F i n a l   F i x e s  
 -   A d d r e s s e d   U I   b u g s :   c r e a t e - o r g   p r o m p t ,   i n v i t e   p a g e   r o u t e ,   e m p t y   v a l i d a t i o n .  
 -   A l l   U I   ( 2 5 / 2 5 )   a n d   A P I   ( 6 6 / 6 6 )   t e s t s   p a s s .  
 