# ADR-0010: Approval lifecycle — needs_approval, the signed one-time override, and grant/deny

Status: accepted (2026-09-03) — implemented and committed in Phase 4 step 2 (`3b59f55`)

## Context

The policy engine (Phase 1) already produces `NEEDS_APPROVAL` in exactly two
places and already reads the approval counter:

- step 10, `SPEND_CAP_EXCEEDED` — cumulative spend `committed + proposal`
  exceeds the cap (ADR-0004 A2: over-cap is `NEEDS_APPROVAL`, not `DENY`);
- step 12, `APPROVAL_REQUIRED` — the action is in the mandate's
  `requires_human_approval_for`;
- step 8, `PAYMENT_BLOCKED_BY_OPEN_APPROVAL` — payment is denied while
  `deal.open_approvals > 0`.

But **nothing opens or closes an approval.** `apply_event` never touches
`open_approvals` (src/mandate/domain/deals.py:80-99), no `DealEvent` exists for
the lifecycle, and there is no approve/reject path. Today `open_approvals` is
only settable by constructing a `Deal` directly, which is how the unit tests
reach the step-8 branch. So the approval flow the test-plan demands
("needs_approval → approve → allow; approval for different amount does not
apply; single-use approval consumed") is unimplemented.

ADR-0004 A2/P2 already fixed the semantics this ADR must honor: a human may
grant a one-time override, **"recorded as its own signed authority record bound
to the specific proposal."** Open spec note #4 (STATE.md) fixes the boundary:
the engine never assumes approval — `PolicyInput` carries no approval field,
`approve → allow` lives in the ledger/boundary, and `evaluate()` stays pure
(invariant 2). ADR-0009 fixed the commit unit and boundary transitions; this
ADR adds the approval branch to it.

## Decisions

### Approval is a boundary/ledger concern; the engine is unchanged

No change to `PolicyInput` or `evaluate()`. `NEEDS_APPROVAL` is a terminal
engine outcome that the **boundary** turns into an open approval. On approval,
the boundary does **not** re-enter the anti-replay gate or re-run `evaluate()`:
the original request already consumed its `request_id`/`nonce`/`idempotency_key`
and logged its decision (ADR-0007/0009), so re-running would return
`IDEMPOTENT_HIT`, not a fresh decision. Approval is a distinct, idempotent act
with its own command id.

### The pending approval (opens in the same transaction as the decision)

When `commit_request`'s decision is `NEEDS_APPROVAL`, the same transaction that
logs the `policy_decision` event also:

- appends an `approval_required` event (`EventType.APPROVAL`);
- opens the approval: `deal.open_approvals += 1`; and
- inserts a `pending` row in a new `approvals` table (migration 0002).

The deal **state** is unchanged — an open approval is an orthogonal counter
(like `open_disputes`), not a state. This makes the engine's step-8 payment
block reachable through the real counter, not a hand-built fixture.

`approvals` table: `approval_id` (ULID, PK), `deal_id`, `request_id`
(originating proposal), `authority_record_id` (parent mandate), `action`,
`amount_minor`, `currency`, `proposal_digest` (canonical digest of the original
proposal — this is what binds the approval to the exact proposal), `reason_code`
(`spend_cap_exceeded` | `approval_required`), `status` (`pending` | `granted` |
`denied`), `decided_by`, `decided_at`, `command_id` (ULID, unique — the
decision's idempotency key), `created_at`.

### The signed one-time override (ADR-0004 A2/P2)

Granting an approval mints an **`ApprovalRecord`** — a signed, single-use
authority record bound to the specific proposal:

- fields: `approval_record_id` (ULID), `deal_id`, `request_id`,
  `parent_authority_record_id`, `action`, `amount_minor`, `currency`,
  `proposal_digest`, `issued_at`; an Ed25519 `signature` over canonical bytes
  (the shared canonicalizer, invariant 13) and the approver's `key_id`.
- **Single-use:** consumed exactly once, when the transition commits.
- **Bound:** `proposal_digest` + `amount` + `action` must match the pending
  approval. A different amount or action is a different proposal and cannot use
  this approval — it must be re-proposed.
- **Signed by the approving principal's key**, loaded at the boundary (in the
  local console the authenticated operator acts for the principal — ADR-0011).
  The override is independently verifiable (invariant 15: principal + authority
  record + decision + event + artifact all present and checkable).

`ApprovalRecord` is a new, deliberately minimal signed domain model. It does not
reuse `AuthorityRecord` (delegation links, spend caps and the action allow/prohibit
lists do not apply to a one-time override), but it is signed and verified by the
same `crypto/` primitives (ADR-0005).

### Grant / deny (`application/approvals.py::decide_approval`)

One boundary call, idempotent by `command_id` (invariant 14). Steps, in order:

1. Load the pending approval by `approval_id`. If absent or already decided →
   `ALREADY_APPLIED`, no event. (This is the single-use + re-approve guard.)
2. **Re-check the parent authority record is still current** at the
   boundary-supplied `now` (`resolve_status`): revoked, expired, or not-yet-valid
   → the approval is **denied** (logged, closed, no transition). This is
   invariant 3 applied at *decision* time, not proposal time.
3. **Re-check the stored deal still permits the original transition** —
   `transition_for(current_state, ACTION_EVENTS[action])` is valid. If the deal
   has advanced and the transition is now stale → **denied** (logged, closed).
   You cannot approve a transition that no longer applies.
4. Operator decision = **grant**:
   - mint + sign the `ApprovalRecord`;
   - in one store transaction (`commit_approval`): append `approval_granted`
     (`EventType.APPROVAL`, `open_approvals − 1`, floor 0) **and** the original
     action's `state_transition` event (carrying the bound amount); update the
     deal row (state + counters).
5. Operator decision = **deny**:
   - in one store transaction (`commit_approval`): append `approval_denied`
     (`EventType.APPROVAL`, `open_approvals − 1`, floor 0); update deal counters;
     no state change.

Every grant and deny appends a decision-visible approval event (invariant 5). No
seen-request or nonce entries are written for the decision — the original request
already owns them (ADR-0007).

### Counters

`open_approvals`: `+1` on `approval_required`; `−1` (floor 0) on
`approval_granted` or `approval_denied`.

These are maintained **in the approval commit path, not via
`apply_event`/`transition_for`**: an approval event changes no deal state, and we
deliberately do not add counter-only state self-loops to the `TRANSITIONS` table
(which models state changes, invariant per ADR-0009). This is the same precedent
as `resolve_dispute`'s dedicated action-level counter rule (ADR-0009) — a counter
rule that is not a transition. The deal's state changes only through the sibling
`state_transition` event on grant (the original action's event).

### Expiry

No separate approval TTL in v0.1. A pending approval lapses only through its
parent record's revocation or expiry, caught by step 2's recheck at decision time
(invariant 7). An approval can never outlive its parent's authority.

## Consequences

- Extends ADR-0009's commit unit with a `NEEDS_APPROVAL` branch
  (`approval_required` + `approvals` row) and adds a third commit method,
  `LedgerStore.commit_approval`. Both backends (in-memory + Postgres) implement
  it; `approvals` table is migration 0002.
- New domain model `ApprovalRecord` (crypto-signed, `crypto/` primitives); the
  lifecycle is recorded as `EventType.APPROVAL` ledger events.
- The engine is untouched — invariant 2 and note #4 hold.
- "Approval for a different amount does not apply" and "single-use" are
  **structural**: the approval is bound by `proposal_digest` + `amount` + `action`
  and consumed once; re-approval is rejected by `status` + `command_id`.
- `decide_approval`'s rechecks (steps 2-3) are the invariant-3/invariant-7
  enforcement point for the approval window.
- Tests pin: needs_approval → approve → allow; wrong-amount no-apply; single-use;
  revoked-at-decision-time → deny; stale-transition → deny; payment blocked while
  open; idempotent re-approve (same `command_id` → `ALREADY_APPLIED`).
- Deferred to Phase 5 (needs the API boundary): concurrent approve/revocation
  races and webhook-retry behavior under the approval path (test-plan §Integration).
