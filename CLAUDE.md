# Agent Mandate — Repository CLAUDE.md

Working repo for the **Agent Mandate** project (working name; folder slug `agent-contracts`,
package name `mandate` per `docs/project-brief.md` §8). Full brief: `docs/project-brief.md`.
Read it before doing any work in this repo.

## What we are building

A policy-enforcing control plane for AI agents: a human issues a signed, scoped, revocable
**mandate** (authority record); a deterministic **policy engine** checks every proposed
action and state transition; an append-only **event ledger** records every decision.

The claim we are proving:

> An untrusted agent can propose actions, but only a valid, current, explicitly scoped
> human mandate can authorize a state change or commitment, and every decision can be
> independently reconstructed from an append-only evidence trail.

Do not optimize for a flashy demo at the expense of this claim.

## Non-negotiable engineering invariants

These are enforced through tests and code review. Do not weaken them for convenience.

1. No model output grants authority. LLM output is an untrusted proposal; a classifier's output is an untrusted observation (invariant 16).
2. The policy engine is deterministic and contains no I/O or model calls. Model-derived claims enter as immutable inputs computed at the boundary, exactly like `signature_valid`.
3. Every state transition rechecks current authority. Checking once at deal creation is insufficient.
4. The event ledger is append-only. Corrections are new events, never edits or deletes.
5. Every allow, deny and approval-required decision is logged.
6. Explicit prohibitions beat allowances. Deny by default if no rule authorizes the action.
7. Revocation and expiration take effect immediately. Revoking a parent delegation invalidates descendants.
8. Financial limits are cumulative across the entire deal, including approved change orders, retries, taxes and fees where applicable.
9. Sensitive disclosure uses an explicit field allow-list. Never rely solely on prompt instructions or post-generation redaction.
10. No payment is captured while a dispute or required approval is open.
11. All externally supplied content is untrusted, including counterparty messages, Agent Cards, webhook payloads, model output and imported documents.
12. Signing keys and secrets never appear in prompts, logs, events, fixtures, client HTML or source control.
13. Every signed object uses deterministic canonical serialization. Signing and verification must reproduce identical bytes.
14. Side effects must be idempotent. Webhook retries or process crashes must not cause duplicate commitments or payments.
15. Every binding action has a traceable principal, authority record, decision, event and resulting artifact.
16. A classifier may only narrow. A content screen's claims can move a decision toward `needs_approval` or `deny`, never toward `allow`; an unavailable screen holds for a person. Model output is untrusted (invariant 11), so a fooled screen costs availability, never authority (ADR-0016).

## Phase-gate rule

Before starting a phase, present a complete breakdown — files to create, tests
to write, order of work, exit criteria, what is explicitly out of scope — and wait
for a go. Do not start phase work on momentum.

## Hard rules for the domain layer (Phases 0–2)

- No database, network, UI, model, or wall-clock calls in domain evaluation.
  Time enters as an explicit immutable input (`now`), supplied by the application boundary.
- Money is integer minor units (e.g. cents). Never floating point.
- The policy engine's only inputs are the immutable `PolicyInput` and only output is
  the immutable `PolicyDecision` (see `specs/policy-schema.md`).
- The state machine is an explicit transition table (see `specs/state-machine.md`),
  not ad-hoc if/else logic.
- Decisions that resolve open questions become ADRs in `docs/decisions/`.
  Never bury them in code. See the open-questions list in the brief (§23).
- A decision that changes direction is recorded as an ADR, or as an amendment
  to the ADR it revises, in the same session it is made — so the "why" stays
  recoverable from the repository alone.

## Stack (v0.1)

- Python **3.13** (brief §7 says 3.12; ADR-0003 settled on 3.13 — 3.13 wins)
- uv for environment and dependency management
- Pydantic v2 for models; Ruff for lint/format; mypy for type checking; pytest + Hypothesis
- FastAPI + PostgreSQL + Alembic + Jinja2 templates (Phases 3–4 — present; the
  console is form-post + autoescaped templates, no HTMX)
- Modular monolith. No microservices. No LLM framework until the deterministic core works. The one model in the tree is a typed classifier behind the `ContentScreen` interface (ADR-0016), optional and off by default.

## Commands

```bash
uv sync                 # install into .venv
uv run pytest           # run tests
uv run ruff check .     # lint
uv run mypy src         # type check
```

## Phases (from brief §16)

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo, specs, invariants, threat model, CI | complete (70bad6b) |
| 1 | Pure domain engine (models, transitions, policy) — no I/O | complete (8e151ef) |
| 2 | Signing, authority lifecycle, anti-replay | complete (18b91a4) |
| 3 | Ledger + persistence (Postgres) | complete (a681b66) |
| 4 | Local API + approval console (FastAPI/Jinja2) | complete (3b59f55 step 2, 32345de step 3) |
| 5 | Two simulated agents, end-to-end + misbehavior | complete (57c58b6) |
| 6 | Separate-machine transport (signed envelopes, ADR-0012) | complete (a48bf43) |
| 7 | Integration pilot — self-run shadow (ADR-0013) | complete (90bb7d1) |
| 8 | Payments, provider sandbox | not started — held pending legal counsel and demand |
| 9+ | Standards adapters, on-chain anchor | not started — held |

Definition of done for Phase 1 is in the brief (§22). Specs: `specs/state-machine.md`,
`specs/policy-schema.md`. Test plan: `docs/test-plan.md`.
