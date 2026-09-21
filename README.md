# Agent Mandate

**The contract layer between agents of different owners.**

> An agent agrees to something on your behalf. Later the other side says the deal
> was for more, or you say your agent was never allowed to agree at all. Today
> neither of you can prove it: chat logs are not evidence, and "the model said so"
> is not authorization.
>
> Agent Mandate makes that provable. A human issues a signed, scoped, **revocable**
> mandate; a deterministic engine checks every action against it; every decision
> lands in an append-only, hash-chained ledger that either side can export and a
> third party can verify against the signer's public key.

> [!WARNING]
> **v0.1, research-grade. Do not deploy this to protect anything real yet.**
> The console is loopback-only with no TLS, the wire has no PKI, and three threat-model
> gaps are tracked by decision — G1 mitigated but not closed, G2 and G3 still open. They
> are named in `docs/threat-model.md` and `SECURITY.md` rather than hidden. It is
> published to be argued with.

> [!CAUTION]
> **Known open defect in the verifier, found 2026-09-21 — do not rely on
> `verify_ledger.py` as an independent check yet.** `verify_bundle()` reads the
> public key out of the same bundle it is verifying, so a bundle fabricated with
> an attacker's own keypair passes: the CLI prints `VERIFIED (18/18 checks
> passed)` and exits 0. The hash chain and the signatures are sound; what is
> missing is any binding to a key the verifier independently trusts. Until
> `verify_bundle` takes the expected key as a required argument, verification
> only proves a bundle is *internally* consistent. Tracked as issue #1.

When two agents act for two different people or businesses, someone has to answer
four questions before anything binding happens: *who authorized this, what exactly
were they allowed to commit to, is that authority still valid right now, and what
can either side show a third party afterwards?*

Agent Mandate answers them deterministically. A human issues a signed, scoped,
**revocable** mandate (an authority record). A deterministic **policy engine**
checks every action the agent proposes and every deal state transition against
that record. An append-only, hash-chained **ledger** records every allow / deny /
approval decision so the full history can be independently reconstructed and
exported.

> **The claim this repo exists to prove:** an untrusted agent can *propose*
> anything, but only a valid, current, explicitly scoped human mandate can
> *authorize* a commitment — and every decision is reconstructable from the
> evidence trail.

This is **not** agent governance (observability, prompt guardrails, agent
identity directories). That space is crowded and well funded. This is the
narrower problem of what makes a cross-owner agent commitment *hold up* —
authority that can be withdrawn, and evidence that survives a dispute.

## See it work

Three self-contained demos, no configuration, no database, no network:

```bash
uv sync
uv run scripts/shadow_pilot.py    # a synthetic field-service day, seven deals
```

A human grants or denies every approval; nothing auto-commits. The run prints
each decision with the rule that produced it, re-verifies every event chain,
and ends in a reproducible digest. Watch for the deals where the agent
overreaches — an over-cap commitment escalated to a person, a prohibited
action refused, a message stopped because it would have leaked the
principal's price floor.

`scripts/sim_agents.py` drives two agents through the console;
`scripts/two_gateways.py` runs two machines exchanging signed envelopes over
real HTTP. Both exit 0 on success.

Then read `docs/project-brief.md` (the full brief) and `CLAUDE.md` (the
invariants) — and `docs/threat-walkthrough.md`, which walks the mechanisms a
malicious agent would actually use and marks each wall Verified, Reasoned or
Gap.

## How this relates to AP2 and A2A

Verified against the published specifications on 2026-09-21: all 11 pages of
the AP2 specification site, plus the A2A specification and its docs tree. AP2's
`main` had not moved since 2026-04-29 at that point. Recheck before citing —
this section ages fast.

**[AP2](https://github.com/google-agentic-commerce/AP2)** (Agent Payments
Protocol, Google-led, Apache-2.0) defines an Agent Authorization model with a
concept it also calls a *Mandate*: a user approves Mandate Content on a Trusted
Surface, open Mandates carry an extensible `constraints` array (required, in the
open-mandate schemas), and a Verifier returns a signed Mandate Receipt. Its
verification rules require that claims from the open mandate appear *unchanged*
in the closed one and that every constraint evaluates successfully, with
"any unknown Constraints MUST be treated as failing evaluation" — so a closed
mandate cannot carry more authority than its parent. AP2 never uses the word
"narrow", but that is the effect, and it is substantially the same shape as this
project's authority record, arrived at independently. AP2 says the model "could
be applied more generally in the future" but currently scopes it to payments and
checkout.

Two things AP2's authorization model does **not** specify:

1. **Revocation.** AP2 defines an `exp` field on all four mandate types and
   recommends setting it "to the smallest value that will allow the Shopping
   Agent to complete the assigned task" — but `exp` is not in the `required`
   set of any mandate schema, there is no mechanism to withdraw a mandate before
   it expires, and no notion of a revoked parent invalidating its descendants.
   AP2's own tracker agrees: issue
   [#45](https://github.com/google-agentic-commerce/AP2/issues/45) has been open
   since 2025-09-18, and its latest comment states that revocation is agreed to
   be necessary but no concrete in-protocol mechanism has been proposed. (AP2's
   sample code ships a `revoke_payment_credential` tool; that revokes a payment
   token, not a mandate, and appears nowhere in the specification.) This repo
   treats revocation as invariant 7 — immediate, and cascading down the
   delegation chain.
2. **An append-only evidence chain.** AP2 does hash-link the artifacts within a
   single transaction: `sd_hash` binds the closed mandate to the open one,
   `checkout_hash` binds payment to checkout, and a receipt's `reference` is a
   hash of the closed mandate. What it does not define is a *ledger*. AP2 states
   that retention and retrieval requirements are "outside the scope of this
   specification", and dispute evidence is scattered across up to five roles
   with no single authoritative record and no retention duty. This repo produces
   an evidence bundle whose summary is signed by the chain key, so a re-export
   that drops the tail and recomputes every hash still fails verification
   (ADR-0015).

This project also models a full deal lifecycle — 18 states, change orders,
disputes, acceptance windows, spend cumulative across the whole deal — where AP2
is scoped to a single checkout.

**[A2A](https://a2a-protocol.org/)** (donated to the Linux Foundation, and
accepted as a Growth Stage project at the Linux-Foundation-directed Agentic AI
Foundation on 2026-08-27) solves agent discovery, task routing and lifecycle. It
declares how to transmit credentials but says itself, in §7.6.4, that it "does
not define the scope, representation, validity, or revocation semantics of the
authorization decision or credential" — and it defines no native scoped,
revocable, human-granted authority credential. Elsewhere it advises that agents
*should* implement credential revocation, which is guidance to implementers with
no protocol mechanism behind it. A2A issue
[#1713](https://github.com/a2aproject/A2A/issues/1713) tracks the cross-org
first-contact accountability gap; as of 2026-09-21 it is still open after 32
comments, none from an account GitHub identifies as a maintainer.

**Known interoperability gap in this repo:** signing here is Ed25519 over a
custom canonical JSON form. The surrounding ecosystem has converged on SD-JWT
VC, OpenID4VP and W3C Verifiable Credentials. Nothing here is wire-compatible
with AP2 today. That is a known, unclosed gap, not an oversight.

## Where we are

Phases 0–7 are complete:

| Phase | What landed |
|---|---|
| 0–1 | Pure domain engine — models, 38-pair transition table, 13-step deterministic policy evaluator. No I/O, no clock, no model calls. |
| 2 | Ed25519 signing, canonical serialization, authority lifecycle, delegation narrowing, anti-replay gate. |
| 3 | Append-only hash-chained event ledger, Postgres persistence, evidence bundles, tamper suites. |
| 4 | Local API + approval console (FastAPI + Jinja2, loopback-only, ADR-0011). |
| 5 | Two simulated agents driving the console end-to-end, misbehavior suite, approve-vs-revoke race. |
| 6 | Separate-machine transport — two gateways sharing no memory, exchanging signed idempotent envelopes over real HTTP (ADR-0012). |
| 7 | Self-run shadow pilot — a synthetic seven-deal field-service day where a human grants or denies every approval (ADR-0013). |
| 7+ | Content screen (ADR-0016) — a typed classifier reads the text an action would send, and may only make the engine *more* careful. Optional, off by default, vendor swappable. |

**1311 tests green** without a database; 1371 with local Postgres (60 tests are
gated on `MANDATE_TEST_DB_URL`). Ruff and strict mypy clean across 59 source
files. Three narrated demos exit 0.

Phase 8 (payments) is **held** pending legal counsel and demonstrated demand;
phase 9 (standards adapters) is held with it. `STATE.md` is the status board,
including the known open items.

## Requirements

- Python **3.13**
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync                    # creates .venv and installs runtime + dev deps
uv sync --extra screen     # additionally installs the TypeSafe content-screen SDK
```

The content screen is optional and **off by default**. `MANDATE_CONTENT_SCREEN`
turns it on: `fixture` (a deterministic keyword screen — no network, used by
the tests and the pilot) or `typesafe` (the vendor adapter, which also needs
`TYPESAFE_API_KEY`). See `specs/content-screen.md` and ADR-0016.

## Commands

```bash
uv run pytest            # run the test suite
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy              # strict type check of src/mandate
```

CI (`.github/workflows/ci.yml`) runs the same three on every push, plus the
gated Postgres suite against a `postgres:16` service.

## Running the local console (Phase 4)

The approval console is a FastAPI + Jinja2 app (server-rendered forms, no
client-side framework). It is the **operator's** surface: propose actions, see
the plain-language reason for every allow/deny/approval, approve or deny, and
revoke mandates. It is bound to **127.0.0.1 only** (ADR-0011).

```bash
uv run scripts/dev_secrets.py              # writes .dev/operator_password + .dev/session_secret (gitignored, 0600)
source .dev/  # or run the two export lines the script prints
uv run python -m mandate.api.app           # serves http://127.0.0.1:8000
```

Log in at `/login` with the operator password (read it with
`cat .dev/operator_password`). Secrets are supplied by env
(`MANDATE_OPERATOR_PASSWORD`, `MANDATE_SESSION_SECRET`) or the gitignored `.dev/`
files, and are never committed, logged, or sent to the browser (invariant 12).
If neither is set, a one-run password is generated and printed to the terminal
so you can still log in — persist it with `scripts/dev_secrets.py`.

## Demos

Each is self-contained and exits 0 on success.

```bash
uv run scripts/sim_agents.py      # two agents + a principal through the console
uv run scripts/two_gateways.py    # two separate-machine gateways over real HTTP
uv run scripts/shadow_pilot.py    # the seven-deal shadow pilot, with its evidence report
```

## Layout

```
src/mandate/
  domain/           # models, state machine, events, lifecycle (no I/O)
  policy/           # the deterministic policy engine (no I/O)
  crypto/           # canonical serialization + Ed25519 signing/verification
  application/      # anti-replay gate + process_request boundary
  ledger/           # hash chain, commit plans, stores, evidence bundles (DB-agnostic core)
  screen/           # the content screen (ADR-0016): questions, protocol, fixture (pure);
                    #   typesafe.py + config.py are the I/O boundary
  api/              # the I/O boundary: FastAPI console (auth, CSRF, Jinja2) — Phase 4
  transport/        # the I/O boundary: two-machine signed-envelope gateways — Phase 6
  pilot/            # the shadow-pilot scenario, driver and evidence report — Phase 7
  adapters/         # postgres/ (schema, PostgresLedgerStore, wire dedup)
specs/              # state-machine, policy-schema, authority-envelope, evidence-bundle,
                    #   content-screen
docs/               # project-brief, threat-model, threat-walkthrough, test-plan, ADR-digest
docs/decisions/     # ADRs (one decision per file)
migrations/         # Alembic (sourced from the same metadata as the tests)
scripts/            # dev_seed, export_evidence, verify_ledger, dev_keys, dev_secrets, demos
tests/              # unit / property / integration (gated) / adversarial
STATE.md            # status board: phases, current numbers, known open items
```

## Not in v0.1 (by decision)

No blockchain (ADR-0002), **no model can widen authority** (ADR-0016), no real
payments, no microservices (ADR-0001). See `CLAUDE.md` for the invariants that
govern all of it.

That middle item used to read "no LLM in the decision path", which was
imprecise once a classifier could force a hold. The accurate statement is the
one the code enforces: a model's opinion may make the engine more careful and
can never make it more permissive.

## Contributing and security

Disagreement is the point. `docs/ADR-digest.md` is the one-screen version of
every decision in `docs/decisions/`, and its last column — "the part worth
poking" — names the weakest point of each one. If a decision looks wrong, open
an issue saying which and what you would change; that becomes an amendment or a
superseding ADR.

Found a security problem? **Do not open a public issue.** Use the Security
tab → *Report a vulnerability*. `SECURITY.md` says what is in scope, what is
a known and documented limitation, and what to expect.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`.
