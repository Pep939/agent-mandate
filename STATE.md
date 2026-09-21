# State

Where the code is. Decisions live in `docs/decisions/` (one file each,
summarised in `docs/ADR-digest.md`); this file is only the status board.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo, specs, invariants, threat model, CI | complete |
| 1 | Pure domain engine — models, 38-pair transition table, 13-step policy evaluator, no I/O | complete |
| 2 | Ed25519 signing, canonical serialization, authority lifecycle, delegation narrowing, anti-replay | complete |
| 3 | Append-only hash-chained ledger, Postgres persistence, evidence bundles, tamper suites | complete |
| 4 | Local approval console (FastAPI + Jinja2, loopback-only, ADR-0011) | complete |
| 5 | Two simulated agents end to end, misbehaviour suite, approve-vs-revoke race | complete |
| 6 | Separate-machine transport — signed idempotent envelopes over real HTTP (ADR-0012) | complete |
| 7 | Self-run shadow pilot — a synthetic field-service day, a human decides every approval (ADR-0013) | complete |
| — | Content screen — a typed classifier that may only narrow (ADR-0016) | complete |
| 8 | Payments, provider sandbox | not started — held pending legal counsel and demonstrated demand |
| 9+ | Standards adapters (AP2 / A2A), on-chain anchor | not started — held |

## Current numbers

| | |
|---|---|
| Tests | 1311 without a database; 1371 with local Postgres |
| Lint / types | ruff check + format and strict mypy clean, 59 source files |
| Demos | `sim_agents`, `two_gateways`, `shadow_pilot` — all exit 0 |
| Shadow pilot | 7 deals, 91 ledger events, 15 messages screened, verdict PASS |

CI runs tests, lint and strict type checking on every push, plus the gated
Postgres suite against a `postgres:16` service.

## Known open items

- **Duplicate-answer gap (application layer).** Under Postgres READ
  COMMITTED, a duplicate of an already-committed request can occasionally
  receive an error answer instead of the stored verdict. Transient — a retry
  re-gates and gets the stored answer — and it never corrupts state or
  commits twice, which `tests/integration/test_postgres_concurrency.py`
  pins. The candidate fix is a read-only re-gate in `process_request` before
  returning an error on `REPLAY` / `STALE_STATE`. Not yet applied.
- **Two-real-machine run.** The two-gateway transport is exercised over real
  HTTP in tests and in a demo, but has not been run across two physically
  separate hosts with a restart in the middle.
- **Interoperability.** Signing is Ed25519 over a custom canonical JSON
  form. The surrounding ecosystem has converged on SD-JWT VC, OpenID4VP and
  W3C Verifiable Credentials, so nothing here is wire-compatible with AP2
  today. Known and unclosed; see the README.
- **Content-screen thresholds** (9000 bp deny, 7000 bp hold) are a
  judgement, not a measurement. They are pinned per screener version and
  changing one is a new ADR, but nothing has calibrated them against real
  traffic.
- **Threat-model gaps G1–G3** remain as documented in `docs/threat-model.md`:
  free-text exfiltration is mitigated but not closed, counterparty identity
  is unverified, and a compromised operator is detectable but not
  preventable.
