# ADR-0001: Modular monolith architecture

Status: accepted (2026-08-31)

## Context

The system has distinct concerns (domain/policy, crypto, ledger, application, adapters)
but v0.1 runs on a single machine for a small number of users. A
microservice split would add network hops, deployment and failure modes before the
core authorization claim is even proven.

## Decision

Build a **modular monolith**: one deployable, one process, with strict internal
package boundaries mirroring the brief §8 layout (`domain`, `policy`, `crypto`,
`ledger`, `application`, `adapters`). Dependencies point inward only:

```
adapters -> application -> policy -> domain
                  \-> crypto
                  \-> ledger
```

- `domain` and `policy` have no outward dependencies and no I/O (invariant 2).
- Adapters are swappable (Postgres now, A2A/stablecoin later) without touching
  domain or policy.

## Consequences

- Fastest path to a testable deterministic core; boundaries are already drawn so a
  later split (if ever justified) is mechanical, not a rewrite.
- Enforced via the import-scan test in `docs/test-plan.md` and code review of
  dependency direction.
