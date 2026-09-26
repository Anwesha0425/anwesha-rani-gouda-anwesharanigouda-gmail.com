// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers: this module only INSERTs.
//
// Two rules from the spec (BRIEF.md §4, PERMISSIONS.md §8):
//   1. DENIED attempts are recorded, not just successes.
//   2. A single action produces a single row — write inside the same transaction
//      as the change. Do NOT also log from a wrapper.
//
// Schema: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
//         result ('allow'|'deny'), reason_code, request_id, at

import { randomUUID } from 'node:crypto';
import { HttpError } from './http.js';

export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  db.prepare(`
    INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    `evt_${randomUUID().replace(/-/g, '').slice(0, 16)}`,
    orgId,
    actorId ?? null,
    action,
    targetType ?? null,
    targetId ?? null,
    result,
    reasonCode ?? null,
    requestId ?? null
  );
}

// Run fn(); if it throws a 403 HttpError (permission error), record the denial and rethrow.
// meta = { action, targetType, targetId }
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? 'missing_permission',
        requestId: ctx.requestId ?? null,
      });
    }
    throw err;
  }
}
