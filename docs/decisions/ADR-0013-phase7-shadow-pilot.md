# ADR-0013: Phase 7 shadow pilot — console-driven, human-in-the-loop, no autonomous commitment, no money

Status: accepted (2026-09-04)

## Context

Brief §16 Phase 7 requires: "Shadow real service transactions without allowing
autonomous commitments. Potential Jobber/CRM/scheduling sandbox adapter, subject
to access and demand. Collect workflow and usability feedback." The validation
intent is to run shadow transactions with **no autonomous commitment and no money
movement**, and to state the result without overclaiming: a passing pilot shows
the invariants hold across a realistic day, and nothing more than that.

Everything Phases 0–6 built is in place: the deterministic policy engine (Phases
1–2), the append-only ledger and approval lifecycle (ADR-0009/0010), the operator
console (ADR-0011), and the two-machine transport (ADR-0012). The remaining question
is not *can the core be broken* (Phases 3–6 answer that) but *does the whole thing
hold together across a realistic, multi-deal day of work with a human in the
approval loop* — the exact shape of a real field-service business. That is what the
shadow pilot answers.

The invariants that bind this ADR:

- **Invariant 1** — LLM output is an untrusted proposal. The pilot's scripted
  steps stand in for what an agent would propose; none of it is trusted.
- **Invariant 3** — every state transition rechecks current authority.
- **Invariant 5** — every allow, deny and approval-required decision is logged.
- **Invariant 10** — no payment is captured while a dispute or required approval
  is open.
- **Invariant 14** — side effects are idempotent.
- **Invariant 15** — every binding action has a traceable principal, authority
  record, decision, event and resulting artifact.

## Decisions

### What "shadow pilot" means in v0.1

A **validation exercise, not a production feature.** It drives a synthetic,
realistic multi-deal portfolio — a "field-service day" for an HVAC/electrical
contractor (quotes, negotiation, agreement, work, change orders, completion,
acceptance, dispute, payment) — through the existing 0–6 stack, and proves the
invariants hold *across the portfolio*. No real customers, no PII, no money. The
output is an independently verifiable evidence report, not a running service.

### Driver: the console path, not the wire path

The pilot reuses ADR-0011's **console** rather than ADR-0012's wire. Reasons:

- The console is the operator surface a real principal actually uses, and it is
  the only path that exercises the full **approval lifecycle** (ADR-0010) that
  "no autonomous commitment" depends on.
- The two-gateway wire is separately proven in Phase 6 (ADR-0012,
  `tests/integration/test_two_gateways.py`). Re-running it adds nothing to the
  pilot's question, which is about the human-in-the-loop loop, not the transport.
- The driver plays every step over real HTTP (starlette `TestClient`) against the
  live FastAPI app: the boundary assembles the signed claim, the engine decides,
  the single writer commits. Nothing is called into the engine directly — the
  scenario is data, not code that bypasses the stack.

### Human-in-the-loop is the no-autonomous-commitment mechanism

Nothing is auto-approved. Every `NEEDS_APPROVAL` decision is resolved by an
**explicit operator grant or deny** — the operator plays the principal. The pilot
records each such human decision as an `Intervention` (actor, action, note), so the
report shows *exactly* where a person had to step in and what they chose. This is
the mechanism that keeps commitments non-autonomous: an agent (or script) can
propose, but a state change on an approval-gated action only happens after a
recorded human grant for that same request.

### No money movement (Phase 8 boundary, invariant 10)

`capture_payment` is human-approval-gated; a deal reaching `CAPTURED` is a **ledger
record, not a charge.** No payment provider is integrated. Phase 8 wires a provider
sandbox; until then capture is authorization + recording only, and the report
asserts that every `CAPTURED` deal did so through a granted `capture_payment`
approval.

### Read outcomes from the store, not the HTML

The driver reads structured outcomes (decisions, current state, pending approvals)
directly from the **same ledger the console wrote** (`state.store`), not by scraping
rendered HTML. This keeps the report independently verifiable and avoids introducing
a second parsing surface that could drift from the ledger.

### Reproducible evidence report + digest (invariant 15)

`build_report` re-verifies each deal's whole event chain (`verify_chain`) and
reconstructs the decision narrative, then checks the two load-bearing invariants:
(a) **no autonomous commit** — no `STATE_TRANSITION` on an approval-gated action
lacks a preceding `APPROVAL(granted)` for the same request; (b) **no money moved**.
The report carries a **digest** (`canonical_sha256_hex` over the normalized
decision/transition/approval sequences). Run-specific ULIDs and timestamps are
deliberately excluded, so re-running the same scenario yields the same digest and
two runs are byte-comparable.

### The CRM/Jobber/scheduling adapter is deferred

The pilot uses **synthetic** scenarios. The ingestion boundary is already specified
and exercised — a mandate minted by the boundary
(`boundary.make_signed_record` / `register_deal`) is how a deal enters the system.
No vendor build is attempted here. The adapter stays gated on account access and
demonstrated demand (brief §16, "subject to access and demand"). Specifying the
boundary without building a speculative Jobber client is the phase-gate-safe
choice.

### Deal-5 dispute-gate subtlety

`PAYMENT_BLOCKED_BY_DISPUTE` (engine step after the transition check) is
**structurally unreachable** in a legitimate flow: the state machine checks
`INVALID_TRANSITION` first, and it never places a deal in a payment-valid state
(`ACCEPTED`/`PAYMENT_PENDING`) while `open_disputes > 0` (a dispute opens only from
`ACCEPTANCE_WINDOW` → `DISPUTED`; `accepted` / resolution zeroes the counter). The
*reachable* dispute gate is `INVALID_TRANSITION` from `DISPUTED`. Deal 5 demonstrates
that reachable gate (open dispute → payment proposed from `DISPUTED` → denied →
resolved → `ACCEPTED` → payment → capture). The `PAYMENT_BLOCKED_BY_DISPUTE` check
is retained as **defense-in-depth** (invariant 10), not removed.

## Consequences

- New package `src/mandate/pilot/`: `scenario.py` (pure data — the six
  `DealSpec`s, no engine calls), `run.py` (the console driver, the `Intervention`
  journal, `PilotRun`), `report.py` (evidence report + digest). I/O (starlette
  `TestClient`) lives at the driver level, mirroring how `api/` is the boundary.
- `scripts/shadow_pilot.py` — self-contained narrated demo; exit 0 if the report
  passes, 1 otherwise. `uv run scripts/shadow_pilot.py`.
- `tests/integration/test_shadow_pilot.py` (11) — pins the portfolio: expected
  terminal state per deal, per-deal `verify_chain`, no-autonomous-commit,
  no-money, over-cap grant and deny, scope-change escalation, dispute gate,
  misbehavior denials, recorded interventions, and a reproducible digest across two
  runs.
- `pilot/` is a **validation harness** (a test/demo driver), placed under `src/`
  so the test and the demo script can import it. It is type-checked by
  `uv run mypy src` and linted by ruff like the rest of `src/`. The invariant-2
  no-I/O AST scan (tests/unit/test_banned_imports.py) still targets the pure core
  (domain/policy/ledger/crypto/application) and is unchanged: `pilot/` depends
  inward on the `api` boundary exactly as a test does, so it introduces no new edge
  into the core.
- **Out of scope for Phase 7:** the CRM/Jobber/scheduling adapter (deferred, above),
  any payment provider (Phase 8), standards adapters and chain (Phase 9), and
  multi-user / TLS / remote operation (carried over from ADR-0011/0012). This ADR
  is a single-operator, loopback, in-memory validation run.
- Tests pin: terminal states, per-deal chain verification, no autonomous commit on
  approval-gated actions, no money moved, over-cap escalation (grant and deny),
  cumulative-cap change order, dispute gate, every misbehavior denial, and digest
  reproducibility across two independent runs.
