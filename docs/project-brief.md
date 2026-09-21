# Agent Mandate Project — Claude Code Handoff Brief

## Purpose of this document

This file gives a new Claude Code session enough context to begin designing and building the project without relying on prior chat history.

The project is currently at **stage zero**:

- No product has been built.
- No repository has been initialized.
- No money has been spent.
- No customers, pilots, investors, or partners have been committed.
- The work completed so far consists of research, concept development, architecture planning, and preliminary specifications.

Treat all names, schedules, business models, and technical decisions as working hypotheses unless explicitly marked as an invariant.

---

# 1. Project thesis

AI agents are beginning to communicate and act on behalf of people and businesses. Messaging protocols can let one agent contact another, but communication alone does not establish:

- Who the agent represents.
- Whether its principal actually authorized it.
- Which actions it may perform.
- What financial limit it has.
- What private information it may disclose.
- Which decisions require human approval.
- When its authority expires or is revoked.
- What evidence exists if an agreement is disputed.

The proposed product is **the contract layer between agents of different owners**.

That framing is deliberate and was chosen over the earlier "authorization,
agreement, and evidence layer for AI agents" on 2026-09-04, then narrowed again
on 2026-09-13 after the market recheck in §4. The earlier framing sits in the
**agent governance** category — observability, prompt guardrails, agent identity
directories — which is crowded and well funded. The contract layer is the
narrower question of what makes a commitment between two *different owners* hold
up: authority that can be withdrawn, and evidence that survives a dispute.

A useful shorthand is **agent contracts**, though this may be too generic for the final company name. The leading working name has been **Mandate**, but no domain or trademark clearance has been completed — and see §20: AP2 now uses "Mandate" as a defined term of art, which makes it a poor distinguishing name.

## Core positioning

> Personal and business agents need explicit, limited, revocable authority before they can safely represent their owners to other agents.

Sharpened after the 2026-09-13 recheck, since the general claim is no longer
differentiating:

> Authority that can be **withdrawn mid-deal and cascade to everything delegated
> beneath it**, and an evidence trail a counterparty can verify **without
> trusting us**, are the two properties the surrounding standards do not
> specify.

## Design principle

> Privacy for the person; accountability for the action.

## Product promise

The owner creates a plain-language mandate defining what an agent may do. The system converts that mandate into a signed, machine-verifiable authority record. A deterministic policy engine checks every proposed action and state transition. The LLM can reason and propose, but it can never authorize, sign, transmit, spend, or commit outside the mandate.

---

# 2. What the product is

The product is a **policy-enforcing control plane** between an AI agent and the outside world.

```text
┌──────────────────── Local / Owner-Controlled Environment ────────────────────┐
│                                                                              │
│  Personal or Business Agent                                                  │
│  - local or hosted LLM                                                       │
│  - reasons, negotiates, drafts                                               │
│  - never holds final authority                                               │
│             │                                                                │
│             ▼                                                                │
│  Deterministic Contract / Mandate Engine                                     │
│  - validates every proposed action                                           │
│  - enforces scope, spending and disclosure limits                            │
│  - rechecks authority on every state transition                              │
│  - triggers human approval                                                   │
│  - signs and logs decisions                                                  │
│             │                                                                │
│             ▼                                                                │
│  Gateway / Integration Layer                                                 │
│  - REST first                                                                │
│  - A2A adapter later                                                         │
│  - CRM, scheduling and payment adapters later                                │
└─────────────┬────────────────────────────────────────────────────────────────┘
              │
              ▼
       Counterparty agent / service

Optional later layers:
- on-chain identity and delegation anchors
- stablecoin or x402 settlement
- public or federated reputation
- selective-disclosure / zero-knowledge credentials
```

## What it is not

- It is not an autonomous LLM making unconstrained deals.
- It is not initially an agent marketplace.
- It is not initially an escrow company.
- It is not initially a cryptocurrency product.
- It is not a replacement for A2A or MCP.
- It is not a legal contract generator pretending that software alone resolves enforceability.

---

# 3. Initial use case

The initial wedge is a bounded service transaction:

1. A customer or customer agent requests a quote.
2. A provider or provider agent returns price, scope and schedule.
3. The agents may negotiate within explicitly defined bounds.
4. Human approval is required for sensitive or binding actions.
5. Work proceeds under the approved terms.
6. Change orders require another authority check.
7. Completion and acceptance are recorded.
8. Payment may be captured after acceptance.
9. A signed evidence bundle can be exported if the parties disagree.

Example mandate rendered for a human:

> Your agent may request generator-maintenance quotes from verified vendors through September 15. It may share your city and generator model, but not your full address. It may negotiate up to $500. It may not accept a quote, authorize payment, or disclose your address without asking you first.

The generator example is useful because the maintainer understands the industry, but the venture must remain industry-neutral unless deliberate validation points toward field services.

---

# 4. Market and protocol context

The market analysis that lived here was internal planning material and has
been removed from the public repository. What survives it is the part that
constrains the code, and that is stated where it belongs: `README.md`
explains how this project relates to AP2 and A2A, including the two things
those specifications do not cover (revocation, and an append-only evidence
chain) and the known interoperability gap (Ed25519 over a custom canonical
JSON form, not SD-JWT VC / OpenID4VP).

---

# 5. Blockchain position

Blockchain is optional infrastructure, not the product thesis.

## Potential advantages

- Portable agent identity.
- Public verification of signatures, registrations and revocations.
- On-chain delegation.
- Stablecoin settlement.
- Neutral timestamping and agreement-hash anchoring.
- Selective disclosure using zero-knowledge credentials.
- Reduced dependence on one platform operator.

## Risks

- AML, sanctions and money-transmission obligations.
- Autonomous laundering and transaction-splitting abuse.
- Wallet/key compromise.
- Gas and onboarding friction.
- Public metadata leakage.
- Pseudonymous actors without real-world accountability.
- Unclear liability when an autonomous agent acts improperly.
- Product distraction before the core authorization engine is validated.

## Current architecture decision

**Do not put blockchain in v0.1.**

Build the contract/mandate engine so it functions fully offline. Introduce blockchain only as an adapter after the local model is correct and there is validated demand.

If blockchain is added later:

- Put identities, revocations, agreement hashes and settlements on-chain only when justified.
- Never put private contract contents, personal data, prompts or long-term agent memory on-chain.
- Keep complete authority records local or encrypted.
- Make autonomous payments opt-in and policy-bound.
- Require human approval above configurable thresholds.
- Treat compliance as a core subsystem, not a disclaimer.

---

# 6. Environment

Notes about the author and their hardware lived here and have been removed.
The operational requirement that came out of them still holds, and it is the
reason for several decisions in this repository: the system must run on one
ordinary machine under Docker Compose, stay readable by someone who is not a
career systems engineer, and prefer being understandable over being clever
(ADR-0001).

---

# 7. Recommended v0.1 stack

Use a deliberately conservative stack:

- **Language:** Python 3.12
- **API:** FastAPI
- **Models and validation:** Pydantic v2
- **Database:** PostgreSQL
- **Migrations:** Alembic
- **ORM/query layer:** SQLAlchemy 2.x, unless plain SQL is demonstrably simpler
- **Signatures:** Ed25519 via PyNaCl or `cryptography`
- **UI:** server-rendered HTML with HTMX; minimal JavaScript
- **Testing:** pytest, pytest-asyncio, Hypothesis where property tests add real value
- **Lint/format/type checking:** Ruff and mypy or Pyright
- **Containers:** Docker Compose
- **Local development:** Makefile or Taskfile with obvious commands
- **Logging:** structured JSON logs, with secrets and private fields redacted

Avoid unnecessary microservices initially. Use a modular monolith with clear boundaries.

Do not add an LLM framework until the deterministic domain layer works. A fake or scripted agent should drive the first end-to-end tests.

---

# 8. Proposed repository

```text
agent-mandate/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── docker-compose.yml
├── .env.example
├── Makefile
├── docs/
│   ├── project-brief.md
│   ├── threat-model.md
│   ├── architecture.md
│   └── decisions/
├── specs/
│   ├── state-machine.md
│   ├── policy-schema.md
│   ├── authority-envelope.md
│   └── evidence-bundle.md
├── src/mandate/
│   ├── domain/
│   │   ├── authority.py
│   │   ├── deals.py
│   │   ├── events.py
│   │   ├── decisions.py
│   │   └── state_machine.py
│   ├── policy/
│   │   ├── engine.py
│   │   └── rules.py
│   ├── crypto/
│   │   ├── canonicalization.py
│   │   ├── signing.py
│   │   └── verification.py
│   ├── ledger/
│   │   ├── models.py
│   │   ├── append.py
│   │   └── verify.py
│   ├── application/
│   │   ├── commands.py
│   │   ├── services.py
│   │   └── approvals.py
│   ├── adapters/
│   │   ├── http_api/
│   │   ├── postgres/
│   │   ├── notifications/
│   │   ├── payments/
│   │   └── a2a/
│   └── main.py
├── templates/
├── static/
├── tests/
│   ├── unit/
│   ├── property/
│   ├── integration/
│   ├── adversarial/
│   └── fixtures/
└── scripts/
    ├── dev_seed.py
    ├── verify_ledger.py
    └── export_evidence.py
```

---

# 9. Non-negotiable engineering invariants

These belong in the repository `CLAUDE.md` and should be enforced through tests and code review.

1. **No LLM output grants authority.** LLM output is an untrusted proposal.
2. **The policy engine is deterministic and contains no I/O or LLM calls.**
3. **Every state transition rechecks current authority.** Checking once at deal creation is insufficient.
4. **The event ledger is append-only.** Corrections are new events, never edits or deletes.
5. **Every allow, deny and approval-required decision is logged.**
6. **Explicit prohibitions beat allowances.** Deny by default if no rule authorizes the action.
7. **Revocation and expiration take effect immediately.** Revoking a parent delegation invalidates descendants.
8. **Financial limits are cumulative across the entire deal**, including approved change orders, retries, taxes and fees where applicable.
9. **Sensitive disclosure uses an explicit field allow-list.** Never rely solely on prompt instructions or post-generation redaction.
10. **No payment is captured while a dispute or required approval is open.**
11. **All externally supplied content is untrusted**, including counterparty messages, Agent Cards, webhook payloads, model output and imported documents.
12. **Signing keys and secrets never appear in prompts, logs, events, fixtures, client HTML or source control.**
13. **Every signed object uses deterministic canonical serialization.** Signing and verification must reproduce identical bytes.
14. **Side effects must be idempotent.** Webhook retries or process crashes must not cause duplicate commitments or payments.
15. **Every binding action has a traceable principal, authority record, decision, event and resulting artifact.**

Claude Code must not weaken these rules for convenience.

---

# 10. Authority record model

The exact schema should be versioned and specified before implementation. Initial fields:

```yaml
schema_version: "0.1"
record_id: "ulid"
principal_id: "owner identity"
agent_id: "authorized agent instance"
counterparty_id: "optional counterparty restriction"
purpose: "human-readable purpose"
allowed_actions: []
prohibited_actions: []
spend_cap:
  currency: "USD"
  amount_minor: 50000
max_negotiation_rounds: 5
acceptance_window_hours: 48
disclosure_fields: []
requires_human_approval_for: []
issued_at: "RFC3339 timestamp"
not_before: "RFC3339 timestamp"
expires_at: "RFC3339 timestamp"
parent_record_id: null
status: "active|revoked|expired"
nonce: "unique anti-replay value"
signature:
  algorithm: "Ed25519"
  key_id: "owner signing key ID"
  value: "base64url signature"
```

## Important modeling rules

- Store money as integer minor units, never floating point.
- Include `schema_version` and migration strategy from the beginning.
- Distinguish identity from authentication credentials.
- Define clock-skew handling.
- Include anti-replay protections: nonce, audience/counterparty, validity interval and request ID.
- Define canonical JSON serialization before signing.
- An authority record describes permission; it does not itself prove that a requested action occurred.

---

# 11. Policy decision model

Every policy evaluation returns a structured result:

```yaml
outcome: "allow|deny|needs_approval"
reason_code: "machine_stable_reason"
explanation: "human-readable explanation"
matched_rule: "rule identifier"
authority_record_id: "record ID"
evaluated_at: "timestamp supplied by application boundary"
input_digest: "hash of evaluated normalized input"
```

## Suggested evaluation order

1. Validate schema version and required fields.
2. Verify signature and canonical payload digest.
3. Check `not_before`, expiration and revocation.
4. Validate delegation chain and parent scope.
5. Validate audience/counterparty and anti-replay properties.
6. Apply explicit prohibited actions.
7. Require action in the allowed-action list.
8. Validate the current deal state permits the action.
9. Validate disclosure fields.
10. Calculate cumulative financial exposure.
11. Check negotiation/resource limits.
12. Trigger human approval where required.
13. Allow only if all prior checks pass.

**Important correction to earlier draft thinking:** signature verification and current time are technically outside a mathematically pure policy function if the function calls cryptographic or clock services. Prefer an application boundary that supplies verified claims and a trusted evaluation timestamp, or make these dependencies explicit immutable inputs. Preserve deterministic replay.

---

# 12. Deal state machine

Initial states:

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

## Initial transition outline

- DRAFT → QUOTE_REQUESTED: authorized request sent.
- QUOTE_REQUESTED → QUOTE_RECEIVED: valid quote accepted as input, not yet agreed.
- QUOTE_RECEIVED → NEGOTIATING: authorized counteroffer.
- QUOTE_RECEIVED/NEGOTIATING → AGREED: both sides approve required terms.
- AGREED → IN_PROGRESS: agreement artifact and signatures exist.
- IN_PROGRESS → CHANGE_REQUESTED: one side proposes altered scope/price.
- CHANGE_REQUESTED → IN_PROGRESS: approved or rejected change, with preserved terms.
- IN_PROGRESS → COMPLETED: provider claims completion.
- COMPLETED → ACCEPTANCE_WINDOW: timer begins.
- ACCEPTANCE_WINDOW → DISPUTED: dispute opened before deadline.
- ACCEPTANCE_WINDOW → ACCEPTED: explicit acceptance or policy-defined timeout.
- ACCEPTED → PAYMENT_PENDING: authorized payment operation begins.
- PAYMENT_PENDING → CAPTURED: payment provider confirms final success.
- DISPUTED → REFUNDED/PARTIALLY_REFUNDED/ACCEPTED: resolution outcome.
- Any eligible state → CANCELLED: authorized cancellation.
- Pre-agreement states → EXPIRED: mandate or offer expires.
- Side-effect failure → FAILED or retryable pending state; never pretend success before provider confirmation.

## Critical state-machine rules

- Every transition is guarded by policy.
- Agreement and payment are separate states.
- External operations use pending states because APIs can fail or time out.
- Silent acceptance must be a configurable policy choice, not a universal default.
- Dispute semantics and payment capture rules need legal and customer validation.
- The system must tolerate duplicate messages and webhook retries.

---

# 13. Event ledger and evidence

The local event ledger provides a tamper-evident history.

Each event should include:

```yaml
event_id: "ULID"
deal_id: "ULID"
sequence_number: 17
event_type: "policy_decision|state_transition|approval|message|artifact|payment"
actor_id: "principal/agent/system/counterparty"
authority_record_id: "ID or null"
previous_event_hash: "hash"
payload_hash: "hash"
occurred_at: "timestamp"
recorded_at: "timestamp"
signature: "system or actor signature"
```

## Ledger requirements

- Append-only database permissions and application semantics.
- Per-deal monotonically increasing sequence number.
- Previous-event hash chain.
- Transactional append with state update or an event-sourced design; avoid state/event divergence.
- Verification utility that detects edits, deletion and reordering.
- Private fields stored separately or encrypted; ledger may store digests rather than raw secrets.
- Retention and deletion policy must reconcile privacy laws with evidence requirements.

## Evidence bundle

Export a portable bundle containing:

- human-readable timeline;
- machine-readable events;
- authority records and revocation status;
- policy decisions;
- signed agreement and change orders;
- message/artifact hashes;
- approval records;
- payment-provider references;
- verification instructions and checksums.

Do not call this legal proof or guarantee admissibility. Call it tamper-evident evidence until counsel advises otherwise.

---

# 14. Approval experience

The usability moat may be more important than blockchain integration.

Design goals:

- Mandates read like ordinary sentences.
- Use templates instead of blank forms: request quotes, schedule service, sell item, approve purchase.
- Show the exact financial exposure and data being disclosed.
- One clear Approve and Decline decision.
- Show what will happen immediately after approval.
- Offer an obvious “Revoke all authority” control.
- Hide cryptographic implementation details from normal users.
- Preserve an advanced view for signatures, hashes and raw JSON.

Example approval:

> Bob's agent proposes $240 for a maintenance kit delivered Tuesday. Approval will authorize this quote only. It will not release payment or disclose your full address. Approve?

The first UI can be local HTMX pages. Mobile push notifications can come later; do not block v0.1 on a native mobile app.

---

# 15. Threat model priorities

A formal threat model is still required. At minimum cover:

- Prompt injection attempting to escape mandate limits.
- Counterparty agent lying about identity, capabilities or task completion.
- Replay of a previously approved action.
- Forged or stolen authority records.
- Signing-key theft.
- Revoked authority reused from cached state.
- Race conditions between revocation, approval and payment.
- Duplicate webhook/payment processing.
- Scope creep through change orders.
- Cumulative spend-cap bypass.
- Data exfiltration through free text, attachments or tool calls.
- Hidden instructions in customer documents.
- Sybil/reputation manipulation.
- Compromised administrator or malicious insider.
- Database tampering and ledger truncation.
- Denial-of-service via endless negotiation or large payloads.
- Autonomous money laundering, sanctions violations and wallet abuse if crypto is added.
- Confused-deputy problems across delegated agents.
- Model hallucination presented as a binding fact.

The primary security boundary is the deterministic gateway, not the prompt.

---

# 16. Development phases

## Phase 0 — Repository and specifications

- Initialize repo and tooling.
- Add this brief and CLAUDE.md invariants.
- Write ADRs for the modular-monolith architecture and no-blockchain v0.1.
- Finalize state-machine and authority-record specs.
- Create threat model.
- Establish CI with lint, type checks and tests.

## Phase 1 — Pure domain engine

- Pydantic/domain models.
- State-transition table.
- Deterministic policy evaluator.
- Unit and property tests.
- No database, network, UI or LLM.

Exit criterion: the policy/state-machine package is replayable and fully tested with plain objects.

## Phase 2 — Signing and authority lifecycle

- Canonical serialization.
- Key generation for development.
- Authority signing and verification.
- Expiration and revocation.
- Delegation-chain validation.
- Anti-replay controls.

## Phase 3 — Ledger and persistence

- PostgreSQL schema and migrations.
- Append-only event recording.
- Hash-chain verification.
- Transactional state updates.
- Evidence bundle export.

## Phase 4 — Local API and approval console

- FastAPI endpoints.
- HTMX screens for mandates, deals, approvals, revocation and timeline.
- CSRF protection, authentication and secret handling.
- Plain-language rendering.

## Phase 5 — Two simulated agents

- Scripted customer and provider agents on one machine.
- Quote, counteroffer, approval, change order, completion and dispute flows.
- Misbehaving-agent scenarios.

## Phase 6 — Separate-machine transport

- Run two gateways on separate machines/networks.
- Mutual authentication.
- Message signatures and idempotency.
- REST envelope first; A2A adapter after core behavior is stable.

## Phase 7 — Integration pilot

- Shadow real service transactions without allowing autonomous commitments.
- Potential Jobber/CRM/scheduling sandbox adapter, subject to access and demand.
- Collect workflow and usability feedback.

## Phase 8 — Payments, only after counsel and demand

- Use provider sandbox/test mode.
- Model authorize/capture/refund explicitly.
- Never describe as escrow without legal clearance.
- Add crypto/x402 only as a separate adapter and risk-reviewed experiment.

## Phase 9 — Standards and chain adapters

- A2A Agent Card and task lifecycle.
- Optional ERC-8004 identity registration.
- Optional on-chain delegation.
- Optional agreement-hash anchor.
- Optional stablecoin settlement.

---

# 17. Testing strategy

Minimum classes of tests:

## Unit tests

- Every transition allow/deny path.
- Every policy rule and precedence case.
- Expiration, revocation and delegation inheritance.
- Cumulative spend and change-order calculations.
- Disclosure allow-list behavior.

## Property tests

- A prohibited action never evaluates to ALLOW.
- Revoked authority never evaluates to ALLOW.
- Increasing spend cannot turn a DENY into ALLOW without a new authority record.
- Ledger verification fails after mutation, deletion or reordering.
- Duplicate idempotency keys cannot create duplicate state transitions.

## Integration tests

- API + database transaction consistency.
- Concurrent approval/revocation races.
- Webhook retries.
- Evidence export and independent verification.

## Adversarial tests

Create a “sloppy/malicious agent” that attempts:

- expired mandates;
- unauthorized disclosure;
- spend-cap bypass through multiple small changes;
- negotiation-loop exhaustion;
- replay of old approvals;
- prompt injection;
- payment before acceptance;
- altered agreement artifacts;
- false completion claims.

---

# 18. Business status and validation

Removed: internal planning material.

---

# 19. Partner conversations

Removed: internal planning material naming specific people.

---

# 20. Naming

Removed: internal planning material.

One conclusion from it is worth keeping, because it affects how this project
should be described in writing: AP2 uses **Mandate** as a defined term of
art, so the bare word is ambiguous in any text that touches both. This
repository says "authority record" for the object and reserves "mandate"
for the concept.

---

# 21. Legal and compliance warnings

Before handling real money, binding agreements or regulated data, obtain qualified counsel on:

- agency law and whether software actions bind the principal;
- electronic signatures and records;
- contract formation and required disclosures;
- payment facilitation, money transmission and escrow terminology;
- consumer protection and automatic acceptance;
- dispute handling and refunds;
- privacy, retention and deletion;
- AML, KYC and sanctions if crypto or agent-controlled wallets are used;
- terms of service, limitation of liability and insurance.

Engineering must not encode business assumptions as legal conclusions.

---

# 22. First Claude Code assignment

Start with Phase 0 and Phase 1 only.

Suggested prompt:

> Read `CLAUDE-PROJECT-BRIEF.md`. Do not implement external integrations, an LLM, payments, blockchain, A2A, UI, or persistence yet. First propose a minimal repository plan for the pure domain package. Identify ambiguities in the authority schema and state machine. Then create `CLAUDE.md`, `specs/state-machine.md`, `specs/policy-schema.md`, and a test plan. Wait for approval before writing implementation code. After approval, implement the policy evaluator and state machine test-first as a deterministic Python package with no I/O.

## Definition of done for the first implementation milestone

- Python project installs in a clean environment.
- Domain models and enums exist.
- Transition table is explicit and reviewable.
- Policy evaluator is deterministic.
- No I/O, database, network, cryptography, UI, LLM or wall-clock calls occur in domain evaluation.
- Tests cover all rules and precedence.
- Ruff, type checking and pytest pass.
- README explains how to run everything.

---

# 23. Open questions Claude should not silently decide

1. Is silent acceptance after an acceptance window appropriate, or should explicit acceptance always be required?
2. Does exceeding a spend cap produce DENY or NEEDS_APPROVAL?
3. How are taxes, tips, fees, refunds and partial captures included in cumulative exposure?
4. Is a counterparty fixed when a mandate is issued, or can discovery occur afterward?
5. How is real-world identity represented without exposing it to counterparties?
6. What actions are generic versus industry-specific?
7. How should delegation depth be limited?
8. How are clock skew and offline revocation handled?
9. Which data belongs in signed events versus encrypted storage?
10. What exactly constitutes agreement between two independently operated gateways?
11. What happens when two sides run incompatible schema versions?
12. Which component owns retry and idempotency behavior?
13. When, if ever, does blockchain add enough value to justify its risks?
14. Is the initial customer the agent developer, the operating business or an integration platform?

Record decisions as ADRs rather than burying them in code.

---

# 24. Final instruction to Claude Code

Build the smallest secure core that proves one claim:

> An untrusted agent can propose actions, but only a valid, current, explicitly scoped human mandate can authorize a state change or commitment, and every decision can be independently reconstructed from an append-only evidence trail.

Do not optimize for a flashy demo at the expense of this claim.
