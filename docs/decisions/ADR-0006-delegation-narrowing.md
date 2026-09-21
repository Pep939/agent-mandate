# ADR-0006: Delegation narrowing is a per-field subset; no depth limit in v0.1

Status: accepted (2026-09-01, maintainer approval of the Phase 2 breakdown)

## Context

`specs/authority-envelope.md` requires a child record's scope to be a **subset**
of its parent's ("narrowing only") and that revoking a parent revokes all
descendants (invariant 7), but does not define subset semantics per field.
Brief §23 question 7 asks how delegation depth is limited.

## Decisions

A child record is valid iff **all** of the following hold relative to its
direct parent:

| Field | Child constraint |
|---|---|
| `allowed_actions` | subset of parent's |
| `prohibited_actions` | superset of parent's (may add prohibitions, never remove) |
| `spend_cap.currency` | equal to parent's |
| `spend_cap.amount_minor` | ≤ parent's |
| `max_negotiation_rounds` | ≤ parent's |
| `disclosure_fields` | subset of parent's |
| `requires_human_approval_for` | superset of parent's (may add gates, never remove) |
| `not_before` | ≥ parent's (child cannot start earlier) |
| `expires_at` | ≤ parent's (child cannot outlive parent) |
| `counterparty_id` | equal to parent's, or child adds a restriction when parent is `null` |
| `parent_record_id` | links the chain; chain must be **acyclic** and **fully resolvable** (every parent available) |

- **Depth:** no limit in v0.1, matching the envelope spec's proposed default.
  A limit, if ever added, is a new ADR.
- **Revocation propagation:** if any ancestor's status is `revoked` (or
  `expired` past `now`), every descendant evaluates as unauthorized. Checked at
  every evaluation (invariant 3), not just at record creation.

## Consequences

- `domain/lifecycle.py` owns these checks as pure functions; the policy engine's
  step 4 consumes their verdict via the boundary-supplied delegation claims.
- Every violation produces a named `delegation_chain_broken` path with the
  specific failing field, for testability and auditability.
