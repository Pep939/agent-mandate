# Spec: Deal State Machine (v0.1)

Status: FINAL for v0.1 (2026-08-31). Ambiguities A1–A8 resolved per
`docs/decisions/ADR-0004-v01-spec-defaults.md`.

## States

```text
DRAFT
QUOTE_REQUESTED
QUOTE_RECEIVED
NEGOTIATING
AGREED
IN_PROGRESS
CHANGE_REQUESTED
COMPLETED
ACCEPTANCE_WINDOW
DISPUTED
ACCEPTED
PAYMENT_PENDING
CAPTURED
PARTIALLY_REFUNDED
REFUNDED
CANCELLED
EXPIRED
FAILED
```

Terminal states: `CAPTURED`, `PARTIALLY_REFUNDED`, `REFUNDED`, `CANCELLED`, `EXPIRED`,
`FAILED` (FAILED is retryable from certain transitions — see below).

## Events

Each event carries an `actor` (principal | agent | system | counterparty), a proposal
payload, and an `idempotency_key`.

| Event | Meaning |
|---|---|
| `quote_requested` | Authorized quote request sent to counterparty |
| `quote_received` | A quote arrived from the counterparty (untrusted input) |
| `counteroffered` | Agent proposes changed terms within mandate |
| `agreement_reached` | Both sides accept required terms |
| `work_started` | Agreement artifact + signatures exist |
| `change_requested` | One side proposes altered scope/price |
| `change_approved` | Change order accepted; new terms now in force |
| `change_rejected` | Change order declined; prior terms preserved |
| `completion_claimed` | Provider claims work complete |
| `acceptance_window_opened` | Acceptance timer begins |
| `accepted` | Explicit acceptance by principal (or timeout, if enabled) |
| `dispute_opened` | Dispute raised before acceptance deadline |
| `payment_initiated` | Authorized payment operation begins |
| `payment_confirmed` | Payment provider confirms final success |
| `payment_failed` | Payment provider reports failure (retryable) |
| `refunded` / `partially_refunded` | Dispute resolution outcome |
| `cancelled` | Authorized cancellation |
| `expired` | Mandate or offer validity lapsed |
| `resumed` | Retry from FAILED back to the pending state |

## Transition table

Format: `FROM --event--> TO` guarded by the listed policy checks. `guard:` references
actions in the closed action vocabulary (`specs/policy-schema.md` §Action vocabulary).

| # | From | Event | To | Guard (policy action) |
|---|---|---|---|---|
| 1 | DRAFT | quote_requested | QUOTE_REQUESTED | `request_quote` |
| 2 | QUOTE_REQUESTED | quote_received | QUOTE_RECEIVED | none (passive input; still logged) |
| 3 | QUOTE_RECEIVED, NEGOTIATING | counteroffered | NEGOTIATING | `counteroffer`; negotiation-round limit |
| 4 | QUOTE_RECEIVED, NEGOTIATING | agreement_reached | AGREED | `accept_agreement` (approval-gated by default) |
| 5 | AGREED | work_started | IN_PROGRESS | `start_work`; agreement artifact hash present |
| 6 | IN_PROGRESS | change_requested | CHANGE_REQUESTED | `propose_change` (either side) |
| 7 | CHANGE_REQUESTED | change_approved | IN_PROGRESS | `approve_change_order`; **cumulative** spend check |
| 8 | CHANGE_REQUESTED | change_rejected | IN_PROGRESS | none beyond authority liveness; prior terms preserved |
| 9 | IN_PROGRESS | completion_claimed | COMPLETED | `claim_completion` (untrusted claim; not acceptance) |
| 10 | COMPLETED | acceptance_window_opened | ACCEPTANCE_WINDOW | none (system; `now` from boundary) |
| 11 | ACCEPTANCE_WINDOW | accepted | ACCEPTED | `accept_completion`; silent timeout only if mandate flag enables it (A1: default off) |
| 12 | ACCEPTANCE_WINDOW | dispute_opened | DISPUTED | `open_dispute` (before deadline only) |
| 13 | DISPUTED | accepted | ACCEPTED | `accept_completion` after resolution |
| 14 | DISPUTED | refunded | REFUNDED | `resolve_dispute(refund=full)`; payment provider confirmation required if money moved |
| 15 | DISPUTED | partially_refunded | PARTIALLY_REFUNDED | `resolve_dispute(refund=partial)` |
| 16 | ACCEPTED | payment_initiated | PAYMENT_PENDING | `initiate_payment`; no open dispute/approval (invariant 10) |
| 17 | PAYMENT_PENDING | payment_confirmed | CAPTURED | provider confirmation; idempotency key match |
| 18 | PAYMENT_PENDING | payment_failed | FAILED | idempotent; `resumed` may retry transition 17/18 |
| 19 | FAILED | resumed | PAYMENT_PENDING | same idempotency key; no double commit (invariant 14) |
| 20 | DRAFT, QUOTE_REQUESTED, QUOTE_RECEIVED, NEGOTIATING | expired | EXPIRED | `now > expires_at`; AGREED included per A5 |
| 21 | eligible (see A4) | cancelled | CANCELLED | `cancel_deal`; never from CAPTURED/REFUNDED |

> **Action → valid-state map.** Each action's valid source states are derived from this
> table: an action's event (ADR-0009) fixes the `From` state(s). `capture_payment` maps
> to `payment_confirmed` (row 17), so its only valid state is `PAYMENT_PENDING` — a code
> decision, since row 17's guard is the *provider's* confirmation rather than a distinct
> policy action (pinned by `test_capture_payment_valid_states`).

## Rules

1. Every transition is guarded by policy. The engine rechecks **current** authority on
   every transition (invariant 3) — including `quote_received`, which is passive input
   and still re-records a decision (logged as allow/deny per invariant 5).
2. Agreement and payment are separate states. Payment never starts before ACCEPTED.
3. External operations use pending states (`PAYMENT_PENDING`); success is asserted only
   on provider confirmation.
4. Idempotency: re-sending the same `(state, event, idempotency_key)` is a no-op that
   returns the original decision, never a duplicate transition.
5. Unknown `(state, event)` pairs are DENIED with reason code `invalid_transition` and
   logged. They never raise.
6. Silent acceptance (timeout) is a configurable mandate option, never a universal default.
7. A dispute or an open required approval blocks payment capture (invariant 10).

## Ambiguities (resolved 2026-08-31 → ADR-0004)

| ID | Question | Decision |
|---|---|---|
| A1 | Silent acceptance after window, or explicit always? | Explicit-only in v0.1; timeout-acceptance is a mandate flag, default off |
| A2 | Spend cap exceeded → DENY or NEEDS_APPROVAL? | NEEDS_APPROVAL (human can grant a one-time override, which is itself a new signed record) |
| A3 | Change order approve AND reject both land in IN_PROGRESS — is one transition enough? | Two events (`change_approved` / `change_rejected`), one destination state |
| A4 | Which states may CANCEL? | Any state except CAPTURED, PARTIALLY_REFUNDED, REFUNDED, CANCELLED, EXPIRED, FAILED-terminated |
| A5 | Is AGREED reachable to EXPIRED? | Yes — an unsigned-agreement window can lapse; mandate `expires_at` applies until IN_PROGRESS |
| A6 | Who owns retry/idempotency semantics? | Domain owns the transition rule; the application layer (Phase 3+) owns retry scheduling |
| A7 | PARTIALLY_REFUNDED/REFUNDED only from DISPUTED, or also post-CAPTURED goodwill refunds? | DISPUTED-only in v0.1; post-capture refund is a separate out-of-scope action |
| A8 | How does the domain observe wall-clock time (windows, expiration) with no I/O? | Boundary supplies trusted `now` per evaluation; domain never calls a clock |
