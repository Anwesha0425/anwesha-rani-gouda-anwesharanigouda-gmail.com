# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

---

### The token's org claim is the isolation boundary, not a WHERE clause

**What I chose:** In `context.js`, I resolve the caller's org from `claims.org` (the token's
payload), not from `params.org` (the URL). Only AFTER membership is confirmed do I cross-check
the URL param against the token's org. A mismatch returns 404, not 403.

**Why:** PERMISSIONS.md §5 says "a resource the caller cannot see is a 404, never a 403, because
a 403 confirms the resource exists." If I looked up by URL param first, I could accidentally reveal
whether an org exists to a user with a token for a different org. The structural fix: the token's
`org` claim IS the caller's org. Requests to other orgs are not filtered — they are invisible
because they can't be named. Commit: `context.js` initial implementation.

**What I rejected:** Filtering-based isolation — build the caller context from the URL, then
filter every query with `AND org_id = ctx.orgId`. This works for the happy path but leaks org
existence via the 403/404 distinction on any path that checks before querying.

**What would change my mind:** If the spec required the error message to include the org name
(e.g., "org_acme does not exist"), that would require knowing the org ID first — but the spec
explicitly says the 404 body must be indistinguishable.

---

### Deny wins before allow, regardless of scope or specificity

**What I chose:** In `resolve()`, I iterate ALL applicable grants and if ANY of them denies the
permission, I return deny immediately. I never check role baseline or allow grants if a deny exists.

**Why:** D1 in PERMISSIONS.md: "An explicit deny always wins. Regardless of scope or specificity:
an org-wide `deny device:terminal` cannot be carved out for one device by a device-scoped allow."
My first model was "last-evaluated wins," which would let a device-scoped allow override an
org-wide deny. That is explicitly the wrong behavior.

**What I rejected:** Last-write-wins (more specific grant overrides broader one). This is the
natural RBAC pattern (AWS IAM, for example, does this for boundary policies vs. identity policies).
It fails here because the spec is explicit that deny beats allow at any scope, and the test fixture
includes a `deny device:terminal` org-wide grant on a device that also has an `allow device:terminal`
grant — the deny must win.

**What would change my mind:** A case where a narrower allow is expected to survive a broader deny.
I cannot construct one from the spec, which itself says this design choice is deliberate.

---

### Role ranks are read from the database, not hardcoded

**What I chose:** `roleRanks(db)` queries `SELECT key, rank FROM roles` every time it is called
for a modification-authority check. I never hardcode `{ owner: 1, admin: 2, operator: 3, ... }`.

**Why:** The README says "Your database is personalised. There is at least one role and one
permission in it that this exercise's prose never mentions. Read the tables; do not encode the
documented matrix." The hidden test fixture will have different roles. An implementation that
hardcodes the 5-role matrix will pass the public suites and fail grading. The `personalise.js`
script generates a role with a rank — my implementation handles it automatically.

**What I rejected:** Hardcoding `const ROLES = { owner: 1, admin: 2, operator: 3, auditor: 4, viewer: 5 }`.
This fails immediately when a 6th role is added at any rank.

**What would change my mind:** If the schema guaranteed the role set was sealed (e.g., a CHECK
constraint on `roles.key`). It doesn't — roles can be inserted freely.

---

### Permission expansion happens in-memory against the DB catalogue

**What I chose:** `expandPattern(pattern, allPermissions)` expands wildcards like `device:*` against
an in-memory array of all permission keys loaded from the database. Expansion is pure JS string
matching — no SQL LIKE queries.

**Why:** The catalogue is small (19 base permissions + custom ones from the personalised fixture).
Loading all permissions once per request and doing string matching is cheaper than one SQL query
per wildcard per grant. The pattern matching logic is simple: `*` → all, `X:*` → keys starting
with `X:`, exact key → [that key] or [].

**What I rejected:** SQL expansion — `SELECT key FROM permissions WHERE key LIKE 'device:%'`.
This would require one query per grant with a wildcard, and the grants query runs before we know
which patterns need expansion. The in-memory approach does it in one pass.

**What would change my mind:** If the permission catalogue were large enough that loading it all
into memory was expensive. At 19+ rows it's trivial.

---

### resolveDevices() batches per-device permission resolution

**What I chose:** The GET /devices endpoint calls `resolveDevices()` which loads grants once and
resolves permissions for all devices in one pass. The device list API embeds the caller's resolved
permissions in each device row.

**Why:** The README explicitly warns: "the console making a follow-up request per device to learn
what it may do" is a performance problem. And: "a list endpoint issuing one query per row" is
another. `resolveDevices()` runs exactly 2 queries (devices list + grants for user in org) instead
of 2+N. This is O(devices) in memory but O(1) in SQL round-trips.

**What I rejected:** Resolving permissions lazily — call `resolve()` once per device inside a
`.map()`. This produces N+2 queries and slows linearly with device count.

**What would change my mind:** If the permission catalogue or grant set grew very large, the
in-memory resolution might consume significant RAM. For the scale in this exercise (hundreds of
devices, hundreds of grants), the batch approach is clearly correct.

---

### Sessions are started with a DB unique index, not a check-then-insert

**What I chose:** `POST /sessions` inserts directly into `sessions` and catches `SQLITE_CONSTRAINT_UNIQUE`
for the `one_exclusive_session_per_device` partial index, converting it to `409 DEVICE_BUSY`.

**Why:** The README says "Two simultaneous exclusive requests must produce exactly one 201 and one 409.
The partial unique index `one_exclusive_session_per_device` is there so the database enforces this
rather than a check-then-insert that races." A check before insert (`SELECT ... WHERE device_id = ?
AND state = 'active'`) reads stale data: two concurrent requests both read "no active session,"
both proceed to insert, and both succeed (TOCTOU race). The DB index makes this impossible.

**What I rejected:** Check-then-insert: `const existing = db.prepare(...).get(deviceId); if (existing) throw deviceBusy()`. This is the obvious implementation and it's wrong under concurrency.

**What would change my mind:** SQLite WAL mode with a single writer means concurrent writes are
serialized anyway. But the schema documentation explicitly says to let the index do it, and the
reasoning holds for any future database.

---

### perm_version is bumped on every authorization-relevant change

**What I chose:** I bump `memberships.perm_version` on: role change, suspension, reinstatement,
removal, grant create, grant revoke.

**Why:** AUTH-DATA-MODEL.md §1: "pv goes up whenever something authorization-relevant changes."
The token's `pv` claim is compared against the membership's `perm_version` on every request. A
mismatch triggers `401 TOKEN_STALE`. This is the mechanism that makes permission changes take
effect on the very next request, not at token expiry.

**What I rejected:** Only bumping on role changes (the "big" changes). This would miss grant
changes, which affect the resolved permission set without changing the role. A user whose
`device:terminal` grant was just revoked would keep seeing the Terminal button until their 15-min
token expired.

**What would change my mind:** If the spec allowed a window between grant revocation and its effect.
It doesn't — "No propagation window and no polling — the very next request reflects the change."

---

### Invite tokens are HMAC-keyed, not raw random hex

**What I chose:** Invite tokens and refresh tokens are hashed with HMAC-SHA256 using a domain key
(`APP_HASH_KEY:invite` and `APP_HASH_KEY:refresh`). The raw token is `randomBytes(32).toString('base64url')`.

**Why:** AUTH-DATA-MODEL.md §2 says "Both are stored hashed — never plaintext, and never
reversible. But they are DIFFERENT credentials, so they get DIFFERENT hash domains." HMAC domains
prevent a value from one table being replayed against the other. Without domains, if an attacker
obtained the raw refresh token they could try it as an invite token hash — the domain prefix
`invite:` / `refresh:` makes the hash spaces disjoint.

**What I rejected:** Plain SHA-256 (no key, no domain). SHA-256 of a 32-byte random value is
computationally secure against brute force, so the key doesn't add security against that attack.
The domain separation is the real reason for HMAC here.

**What would change my mind:** If the application key (`APP_HASH_KEY`) were known to an attacker
(e.g., leaked via environment variable dump), they could pre-compute the hash. At that point the
scheme is broken anyway.

---

### Audit log writes happen inside the mutation transaction

**What I chose:** Each route that writes an audit row does so inside the same `db.transaction()`
block as the mutation. If the mutation rolls back, the audit row doesn't exist.

**Why:** BRIEF.md §4: "Write the success row inside the same transaction as the change it describes;
do not also log the allow from a wrapper." A wrapper that always logs would record a "allow" for
an operation that then fails, creating a false positive in the audit log. The one-transaction
approach means the audit row exists if and only if the mutation committed.

**What I rejected:** A middleware/wrapper that logs after every successful response. This is easier
to write but produces double-logging (the wrapper + the route), and the spec explicitly prohibits it.

**What would change my mind:** If the audit log needed to record the response body (e.g., which
grant was created), a wrapper would need to run after the response is known. But the schema only
has `target_id`, which I know before the response.

---

## Where this repo argues with itself

**AUTH-DATA-MODEL.md §10 says `pv` staleness is handled by `verifyAccessToken`:**
> "a token whose pv is stale, as 401 TOKEN_STALE"

But `verifyAccessToken` doesn't have access to the database — it only verifies the JWT signature
and claims. The perm_version check requires a database lookup. I implemented it in `context.js` via
`assertFresh(claims, membership)`, not inside `verifyAccessToken`. The check is equivalent but
lives in the right place (where db is available). I built against the intent, not the location.

**PERMISSIONS.md §3 says "org-level = union across all devices":**
The phrase is ambiguous. Does it mean: (a) the union of all device-level resolutions, or (b)
applying only org-wide grants (no device-scoped ones)? I built against interpretation (b): at
org-level, only org-wide grants apply. Device-scoped grants are only evaluated when you ask about
that specific device. This makes a viewer with a device:control grant on one device show the
Control button on that row (device-level) but not in the nav (org-level). I believe this is correct
because if org-level included device-scoped grants, a viewer with ONE device:control grant would
see the Control nav item even if they have no device:control on the currently-selected device.

## Deliberately not built

- **Rate limiting:** explicitly excluded by the spec
- **Email delivery:** spec says tokens are returned in API responses, not emailed
- **Password reset:** spec excludes it as "Q2"
- **Real remote access:** session is a record; no screen capture, no shell
- **Refresh token blacklist (Redis/in-memory):** using DB-backed revocation only, which is correct
  and sufficient for the scale described
