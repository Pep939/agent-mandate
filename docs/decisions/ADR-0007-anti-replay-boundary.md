# ADR-0007: Anti-replay is a boundary component; idempotency-key reuse conflicts reject

Status: accepted (2026-09-01, maintainer approval of the Phase 2 breakdown)

## Context

`specs/policy-schema.md` §Anti-replay assigns the seen-request store to the
boundary (Phase 3+); the pure engine checks shape only. `replay_detected` and
`missing_field` are boundary-owned reason codes. Phase 2 needs the boundary
component to exist and be tested before the ledger (Phase 3) gives it
persistence.

## Decisions

- **Location:** `src/mandate/application/anti_replay.py`. A
  `SeenStore` protocol plus an in-memory implementation; Phase 3 replaces the
  implementation with Postgres, not the interface.
- **What is tracked:**
  - record `nonce` — a nonce names exactly **one** `record_id`. The record is
    presented on every `PolicyInput`, so re-presenting a known record with its
    own nonce is normal; a nonce previously seen on a **different**
    `record_id` is a REPLAY (nonce collision = replay/forgery attempt).
  - `request_id` — seen once per evaluation request.
  - `idempotency_key` — mapped to `(proposal canonical digest, decision)`.
- **Verdicts:**
  - `PASS` — proceed to `evaluate()`;
  - `REPLAY` — a `request_id` previously evaluated, or a nonce collision across
    different records (boundary reason code `replay_detected`);
  - `IDEMPOTENT_HIT` — same `idempotency_key` **and** identical proposal digest:
    return the stored original decision, never re-evaluate (state-machine rule
    4: re-sends are no-ops);
  - `CONFLICT` — same `idempotency_key` with a **different** proposal digest:
    **reject**. A key names exactly one proposal; reusing it for a different
    proposal is an invariant-14 (idempotent side effects) violation and is
    treated as hostile input, not a retry.
- **Gate order (load-bearing):**
  1. `idempotency_key` known + digest match → `IDEMPOTENT_HIT`;
  2. `idempotency_key` known + digest mismatch → `CONFLICT`;
  3. `request_id` seen → `REPLAY`;
  4. nonce collision across records → `REPLAY`;
  5. otherwise `PASS` (and on first sight, register nonce→record and
     `request_id`).

  The idempotency check runs **first** because a crash-retried request
  legitimately reuses its `request_id` and `idempotency_key` with an identical
  proposal; it must get the original decision back, not a replay verdict
  (invariant 14).
- **Remembering:** after any `PASS` evaluation, the boundary stores
  `(idempotency_key → digest, decision)` and registers the
  nonce→record mapping, regardless of the outcome — a denied proposal is still
  consumed and its retry returns the same denial.
- The gate runs **before** `evaluate()`; a rejected request never reaches the
  policy engine and no state is touched.
- **Scope of memory:** v0.1 in-memory is process-lifetime; the threat model's
  "revoked authority reused from cached state" is closed by re-checking
  current authority on every evaluation (invariant 3), not by store TTLs.

## Consequences

- `evaluate()` remains pure and unchanged; determinism property tests still
  hold.
- Phase 3 must persist `SeenStore` atomically with the ledger append so a crash
  between gate and ledger cannot double-process (invariant 14).
