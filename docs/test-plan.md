# Test Plan (v0.1)

Status: in force. Written for Phase 1, extended phase-by-phase as the plan was
approved and delivered (Phases 1–7 + C1–C3 complete; 1185 tests green with a
database — 1125 + 60 Postgres-gated that need `MANDATE_TEST_DB_URL`).

Guiding claim under test (brief §24): an untrusted agent can propose actions, but only
a valid, current, explicitly scoped human mandate can authorize a state change, and
every decision is reconstructable from the evidence trail.

## Phase 1 scope: pure domain, no I/O

All Phase 1 tests run on plain objects. No database, network, crypto, UI, LLM, or
wall-clock. `now` and verified claims are constructed inputs.

### Unit tests

- **Transition table**: every row in `specs/state-machine.md` exercised in both
  directions — the transition exists AND the unlisted pairs deny with
  `invalid_transition`. Terminal states admit nothing.
- **Policy rules**: one test per evaluation-order step; each reason_code in
  `specs/policy-schema.md` produced by at least one test.
- **Precedence**: prohibited action present in both `prohibited_actions` and
  `allowed_actions` → deny. Revoked record with otherwise-perfect proposal → deny.
  Expired record → deny. Not-yet-valid record → deny.
- **Spend**: exact-cap pass; cap+1 minor deny/needs_approval (per A2 decision);
  cumulative across multiple change orders; currency mismatch.
- **Disclosure**: field in allow-list passes; any other field (including "harmless"
  ones) fails; empty allow-list blocks all disclosure fields.
- **Approval**: needs_approval → approve → allow; approval for different amount does
  not apply; single-use approval consumed.
- **Idempotency shape**: identical proposal structure accepted; malformed ids rejected
  at validation.

### Property tests (Hypothesis)

1. A prohibited action never evaluates to `allow` for any generated input.
2. A revoked or expired authority record never evaluates to `allow`.
3. Monotonicity: increasing `proposal.amount_minor` cannot turn `deny` into `allow`
   without a larger spend cap in the input.
4. Determinism: `evaluate(x) == evaluate(x)` byte-for-byte for any generated input.
5. Deny-by-default: any input with a deliberately broken/missing field set evaluates
   to `deny` (never raises).
6. Transition determinism: same `(state, event, input)` always produces the same
   result; unknown pairs always deny.

### Adversarial fixtures (domain-level, Phase 1)

A "sloppy/malicious agent" fixture set — proposals only, no live agent yet:

- Expired mandate reused after `expires_at`.
- Disclosure of a field outside the allow-list.
- Spend-cap bypass via many small `approve_change_order` increments.
- Negotiation-round exhaustion (rounds = cap, cap+1).
- Replay-shaped duplicate proposal (boundary-replay reason path).
- Payment initiation while a dispute is open.
- Payment initiation with an open required approval.
- Counterparty mismatch on an audience-restricted record.
- Schema downgrade attack (`schema_version` older/newer than engine).

### Integration + adversarial (live agents)

- **Delivered in Phase 3** (gated on `MANDATE_TEST_DB_URL`): DB transaction
  consistency (rollback leaves no partial state), stale-commit no-ops, command
  idempotency against the persisted seen-store, the append-only trigger
  (UPDATE/DELETE blocked at the database), Alembic-migration equivalence, and
  evidence export verification (`verify_ledger.py`, tamper suites B/C).
- **Delivered in Phase 5** (`tests/adversarial/`, live uvicorn server, real
  HTTP): two-agent end-to-end flows (lifecycle to payment captured, approval
  deny + re-grant, dispute open/close, payment blocked while the capture
  approval is open), 13 misbehavior scenarios (out-of-scope action,
  prohibition, per-action and cumulative spend caps, invalid state, revoked,
  expired, tampered mandate, round flood, unauthenticated / foreign-CSRF /
  unknown-action / stale-boundary denials), and the concurrent
  approval-vs-revocation race under real parallelism (either landing order
  consistent, chain always verifies). Each flow ends with an independent
  `verify_chain` over the whole deal.
- **Delivered in Phase 6** (transport, ADR-0012; `src/mandate/transport/` +
  `tests/integration/test_two_gateways.py` + `tests/adversarial/test_gateway_abuse.py`
  + `tests/adversarial/test_receipt_tampering.py`):
  two gateways that share no memory, exchanging signed, idempotent envelopes over
  real HTTP. `test_envelope.py` (35) pins the pure signed-envelope layer —
  canonical-bytes sign/verify, tamper, cross-record non-transfer, unknown peer,
  wrong algorithm — and the counterparty-side receipt-verify path
  (`TestVerifyReceipt`: genuine verifies; tampered payload, wrong sender,
  forged sender identity, replayed-for-another-message, non-receipt kind,
  stale, and freshness-window-without-now are each rejected).
  `test_two_gateways.py` (7) drives a full deal across the wire
  (proposal → counterparty event → over-cap escalation), asserts the wire-level
  idempotency key returns the stored answer on a byte-identical redelivery (no
  duplicate state, invariant 14), and ends with an independent `verify_chain` on
  each ledger. `test_gateway_abuse.py` (10) is the adversarial transport suite:
  forged sender, tampered payload, idempotency-key reused for different content
  (ADR-0007 wire-level), unregistered attacker, and further envelope-shape
  attacks — each commits nothing and the ledger still verifies.
  `test_receipt_tampering.py` (5) is the counterparty-side receipt-forgery
  suite: a genuine receipt verifies through the production `verify_receipt`
  path, while an attacker-forged, a tampered, a replayed (genuine but for a
  different message), and a stale receipt are each rejected before the outcome
  is read — the same path `scripts/two_gateways.py` runs on every response.
- **Delivered in Phase 7** (integration pilot, ADR-0013; `src/mandate/pilot/` +
  `tests/integration/test_shadow_pilot.py`): a self-run shadow pilot drives a
  synthetic, realistic field-service day (seven deals — standard paid call,
  over-cap grant, over-cap deny, cumulative-cap change order,
  dispute-during-acceptance, a misbehaving agent, and the content-screen deal
  added by ADR-0016) through the real console
  + policy + ledger over HTTP, with a human grant/deny on every approval. The
  11 tests pin the portfolio: expected terminal state per deal, per-deal
  `verify_chain`, **no autonomous commit** (no state change on an
  approval-gated action without a preceding principal grant), **no money moved**
  (every `CAPTURED` deal went through a granted `capture_payment`), over-cap
  grant vs. deny, cumulative-cap change order, the dispute gate, every
   misbehavior denial, recorded human interventions, and a **reproducible
   digest** across two independent runs. No payment provider is integrated;
   capture is a ledger record (real movement is Phase 8).
 - **Delivered with C1** (key custody + runnable gateway + restart-safe
   persistence; `scripts/run_gateway.py` + `scripts/dev_gateway_keys.py`):
   `tests/unit/test_gateway_process.py` (31) pins the process helpers —
   identity / chain-key / peer loaders (roundtrip, mismatched stored public
   key, missing seed, corrupt JSON, malformed and id-mismatched peer
   entries), env parsing (`require_env`, `max_age_from_env` incl. the
   `0`/`off`/`none`/`disabled` off-switches), and the secret-redacting JSON
   formatter (top-level and nested sensitive keys → `***redacted***`,
   non-sensitive values survive). `tests/integration/test_restart.py`
   (gated) is the restart-safety proof: seed a deal + two events through
   the key files, close the store, then **re-bootstrap from the same files
   + same DB** and assert the deal → mandate registry rehydrated, the
   chain re-verifies under the reloaded chain key, the mandate still
   `verify_record`s, and the pre-existing deal stays actionable (a further
   transition commits and the grown chain still verifies).
   `test_two_gateways.py` (+2) pins the `issued_at` freshness window: a
   first-seen envelope outside the window is rejected with no commit (and
   the idempotency key is not poisoned — a fresh retry is accepted), while a
   **stale redelivery still returns the stored answer** (invariant 14).
   `test_envelope.py` (+5 `TestFreshness`) pins `envelope_is_stale` as a
   pure symmetric predicate; `test_ledger_store.py` / `test_postgres.py`
   (+`TestDealLinks`, gated) pin the `deal_links` registry on both backends
   (link + list, same-pair relink idempotent, different-record relink
    rejected) and extend the append-only trigger / least-privilege-role
    matrices to the ninth governed table.
  - **Delivered with C3** (shared commit plans + claim-first anti-replay;
    `src/mandate/ledger/commit_plans.py`): `tests/unit/test_commit_plans.py`
    (10) pins the single planner — pure policy content for identical inputs
    (same `payload`/`payload_hash`, unique `event_id` nonce), decision-only
    deny, the pending-approval shape (approval row + `APPROVAL` event +
    `open_approvals` increment), grant → transition + approval closed, grant
    with a revoked parent → forced deny (invariant 7), operator deny,
    revocation event, and a cross-plan chain that `verify_chain`s.
    `tests/integration/test_postgres_concurrency.py` (gated) is the TOCTOU
    proof: 8 threads fire the **same** `process_request` behind a barrier —
    exactly one `COMMITTED`, every duplicate an `IDEMPOTENT_HIT` carrying the
    stored decision, state advanced once, two events, no exceptions
    (pre-fix the same test had 4 of 8 workers double-commit the request);
    and 8 threads fire the same `commit_transition` command — one `COMMITTED`,
    the rest `ALREADY_APPLIED`, one event.

## Phase 1 exit criteria (brief §16)

- Every rule, reason_code, and transition has a named test.
- Property tests 1–6 pass under Hypothesis default settings (raise examples if time allows).
- `uv run pytest`, `uv run ruff check .`, and `uv run mypy src` all pass in a clean environment.
- No import in `src/mandate/domain` or `src/mandate/policy` touches `socket`,
  `subprocess`, `os.environ` secrets, a database driver, or a clock. (Enforced by a
  test that scans the module AST for banned imports.)

## Tooling

- pytest, pytest-asyncio (later phases), Hypothesis
- Ruff (lint + format), mypy (strict on `src/mandate`)
