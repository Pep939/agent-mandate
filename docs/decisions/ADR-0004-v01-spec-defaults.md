# ADR-0004: v0.1 defaults for state-machine and policy ambiguities

Status: accepted (2026-08-31, maintainer approval of proposed defaults)

## Context

`specs/state-machine.md` (A1–A8) and `specs/policy-schema.md` (P1–P3) each carry
proposed defaults for the brief's open questions. The maintainer reviewed the table
and accepted all proposed defaults. This ADR records them so they are decisions,
not code comments.

## Decisions

| ID | Decision (v0.1) |
|---|---|
| A1 | Acceptance is **explicit-only** by default. Timeout-acceptance exists as a mandate flag (`silent_acceptance: bool = false`) and is off unless the principal opts in. |
| A2 | Spend-cap excess yields **NEEDS_APPROVAL**, not DENY. A human may grant a one-time override, recorded as its own signed authority record bound to the specific proposal. |
| A3 | Change orders use **two events** (`change_approved`, `change_rejected`) with one destination state (IN_PROGRESS). |
| A4 | CANCEL is allowed from any state **except** CAPTURED, PARTIALLY_REFUNDED, REFUNDED, CANCELLED, EXPIRED. |
| A5 | AGREED **can** expire — `expires_at` applies until IN_PROGRESS. |
| A6 | The **domain** owns the transition/idempotency rule; the **application layer** (Phase 3+) owns retry scheduling. |
| A7 | Refunds are reachable **only from DISPUTED** in v0.1. Post-capture goodwill refunds are out of scope. |
| A8 | The domain **never calls a clock**. The application boundary supplies a trusted `now` in `PolicyInput`. |
| P1 | Action vocabulary is a **closed 13-token set**. Extension happens in schema `0.2` via a versioned vocabulary table, never free text. |
| P2 | Over-cap money handling is the same rule as A2: NEEDS_APPROVAL with signed one-time override. |
| P3 | v0.1 cumulative exposure = **agreed total price only** (incl. approved change orders). Itemized tax/fee/tip/refund accounting arrives with the payments phase (Phase 8). |

## Consequences

- The specs' `AMBIGUITY` markers are resolved; specs are finalized for Phase 1.
- Any future change to a row here is a new ADR (supersede this one), never a
  silent code change.
- A2/P2 make the approval flow load-bearing: the approval UX (brief §14) must
  handle spend-override approvals, not just action approvals.
