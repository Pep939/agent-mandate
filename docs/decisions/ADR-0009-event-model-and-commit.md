# ADR-0009: Event model, hash chain, and the transactional commit unit

Status: accepted (2026-09-01, maintainer approval of the Phase 3 breakdown)

## Context

Brief §13 defines the event fields and ledger requirements; §16 Phase 3
requires append-only recording, hash-chain verification, and transactional
state updates. The policy engine (Phase 1) decides but never fires a
`DealEvent`, and the state machine maps `(state, event) → state` but nothing
maps `ActionToken → DealEvent`. Those gaps are application-layer concerns this
ADR closes. Open question §9 (signed events vs encrypted storage) is answered
for v0.1: ledger payloads carry only non-sensitive data plus **digests** of
sensitive artifacts, never raw secrets.

## Decisions

### Event model (`domain/events.py`, pure)

Fields per brief §13, plus two derived-and-stored hashes:

- `payload_hash = SHA-256(canonical_bytes(payload))` — validated at
  construction (a mismatched hash raises).
- `event_hash = SHA-256(canonical event form)` where the canonical event form
  excludes `signature` and `event_hash` itself. The gateway's Ed25519
  signature covers exactly those bytes (invariant 13, one canonical
  algorithm). Validated at construction.
- Canonical bytes come from `crypto/canonicalization.py`.

### Hash chain

- Per-deal, 0-based monotonically increasing `sequence_number`.
- First event of a deal: `previous_event_hash = GENESIS_HASH` (64 zero hex
  chars). There is **no separate genesis row**.
- Event N+1's `previous_event_hash := event_hash` of event N. Any edit,
  delete, or reorder of an event breaks the chain and is detected by
  `verify_chain` (which recomputes every hash, checks linkage and sequence,
  and verifies every signature).
- **The gateway Ed25519 key signs every event** (`signature.key_id` stored).
  Per-actor event signing is deferred.
- `occurred_at` = trusted boundary `now`; `recorded_at` = boundary-supplied
  commit time. The domain never calls a clock (invariant 2, A8).
- `event_type` vocabulary is the fixed 6 from brief §13
  (`policy_decision, state_transition, approval, message, artifact, payment`).
  Extension is a schema `0.2` change, never ad hoc (same rule as the action
  vocabulary, ADR-0004 P1).

### Action → event mapping (`domain/state_machine.py`)

`ACTION_EVENTS: dict[ActionToken, DealEvent | None]`:

| Action | Event |
|---|---|
| request_quote | quote_requested |
| counteroffer | counteroffered |
| accept_agreement | agreement_reached |
| start_work | work_started |
| propose_change | change_requested |
| approve_change_order | change_approved |
| claim_completion | completion_claimed |
| accept_completion | accepted |
| open_dispute | dispute_opened |
| initiate_payment | payment_initiated |
| capture_payment | payment_confirmed |
| cancel_deal | cancelled |
| resolve_dispute | **None (decision-only; resolution outcomes are separate events)** |

A pinned test asserts: for every action and every state in
`ACTION_VALID_STATES[action]`, `transition_for(state, ACTION_EVENTS[action])`
is a valid transition (decision-only actions excepted). The mapping can never
drift from the transition table silently.

### Deal counter updates (pure, two functions)

`apply_event(deal, event, target_state, amount_minor) -> Deal`
(`domain/deals.py`; the target state is computed by the caller so `deals.py`
keeps no import of `state_machine.py` — the enum direction is one-way):

| Event | Counter effect |
|---|---|
| counteroffered | `negotiated_rounds += 1` |
| agreement_reached | `committed_minor += amount` (0 if none) |
| change_approved | `committed_minor += amount` (0 if none) |
| dispute_opened | `open_disputes += 1` |
| accepted (from DISPUTED) | `open_disputes = max(0, open_disputes - 1)` |
| refunded / partially_refunded | `open_disputes = 0` |
| all others | no counter change |

`apply_action(deal, action, amount_minor) -> Deal`
(`domain/state_machine.py`, composes the table with `transition_for`):

- resolves the action's event, computes the target state (raises `ValueError`
  if the pair is not in `TRANSITIONS`), and applies `apply_event`;
- **`resolve_dispute` is the one action-level counter rule:** no state
  change, `open_disputes = max(0, open_disputes - 1)`. Without it, a dispute
  opened via `open_dispute` could never be closed by resolution and the
  deal would stay payment-blocked (engine step 8) forever.

Consistent with ADR-0004 P3 (v0.1 cumulative exposure = agreed total incl.
approved change orders). Refund events have no action token in v0.1; they are
boundary/operator transitions, still recorded through the same commit path.

### The transactional commit unit

One `LedgerStore.commit_request(CommitRequest)` is exactly **one transaction**:

1. load the stored deal (source of truth — never the boundary's claimed copy)
   and the chain head;
2. **recheck** the transition against stored state (invariant 3); if the
   boundary's view is stale, abort with `stale_state` and write nothing;
3. append the `policy_decision` event **always** (allow, deny and
   needs_approval are all logged — invariant 5);
4. if the decision is ALLOW and the action maps to an event: append the
   `state_transition` event and update the deal row (state + counters);
5. register the seen-store entries (nonce→record, request_id,
   idempotency_key→(digest, decision)) regardless of outcome — a denied
   proposal is still consumed (ADR-0007);
6. commit. Any failure before commit rolls back everything.

Consequences: DENY decisions consume a sequence number in the deal's chain;
a stale concurrent commit appends nothing (threat model: revocation/approval/
payment races); the idempotency-key→decision mapping is durable, so Phase 4
retries return the stored decision after a restart.

### Boundary-originated transitions

Several `DealEvent`s have no action token in v0.1 (`quote_received`,
`acceptance_window_opened`, `change_rejected`, `payment_failed`, `refunded`,
`partially_refunded`, `expired`, `resumed`). They are fired by the boundary /
operator (counterparty webhook, expiry sweep, dispute resolution) through a
second commit path, `commit_transition(TransitionRequest)`:

- one state_transition event, same chain, same gateway signature;
- rechecks the transition against stored state (`stale_state` abort otherwise);
- applies the same `apply_event` counter rules;
- carries a boundary-chosen `command_id` (ULID, e.g. the webhook delivery id)
  stored in a `seen_commands` table: a retry of the same command is a
  no-op returning `ALREADY_APPLIED` — webhook retries cannot double-count
  negotiation rounds or committed spend (invariant 14).

No policy decision, seen-request, or nonce entries are written for boundary
transitions.

### Deal creation

`create_deal` inserts the deal row **without an event** — the chain begins
with the first logged decision. The deal row carries `created_at` and
parties and is included in evidence bundles. A dedicated creation event, if
ever wanted, is a schema `0.2` vocabulary addition.

## Consequences

- `process_request` (application layer) is the only writer: gate →
  evaluate → commit. Rejected gate verdicts (replay/conflict) write nothing.
- The event model's construction-time hash validation makes an
  inconsistent event unconstructible, so `verify_chain` is a pure reader.
- `guarded_evaluate` (Phase 2) is superseded by `process_request`; the pure
  `check_anti_replay` gate is retained and now runs against the durable store.
