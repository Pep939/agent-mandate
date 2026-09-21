# ADR-0012: Separate-machine transport — gateway identity, wire envelope, idempotency

Status: accepted (2026-09-03)

## Context

Brief §16 Phase 6 requires: "Run two gateways on separate machines/networks.
Mutual authentication. Message signatures and idempotency. REST envelope
first; A2A adapter after core behavior is stable."

Up to now everything ran against one local console (ADR-0011). Phase 6
introduces the second machine: each party runs its own copy of the monolith
(ADR-0001 — two copies, not a rewrite) with its own ledger, and the two
gateways exchange messages over HTTP. The invariants that bind this ADR:

- **Invariant 1** — LLM output is an untrusted proposal. A `proposal` arriving
  on the wire can only cause a state change via the *receiving* gateway's
  deterministic policy engine.
- **Invariant 11** — all externally supplied content is untrusted, including
  counterparty messages. The wire is the first genuinely hostile input surface
  (ADR-0011's surface was the local operator).
- **Invariant 13** — every signed object uses deterministic canonical
  serialization.
- **Invariant 14** — side effects are idempotent; retries and redeliveries
  must not duplicate commitments.
- **Invariant 15** — every binding action has a traceable principal,
  authority record, decision, event, and resulting artifact.

ADR-0005 fixes Ed25519 + one canonical serializer; ADR-0007 fixes the
request-level anti-replay rule (same key + same proposal → original decision;
same key + different proposal → hostile). ADR-0011 explicitly deferred TLS
and two-machine operation to this phase. The engine already enforces an
audience check (step 5: `record.counterparty_id` must equal
`pi.counterparty.id`), which this ADR puts on the wire.

## Decisions

### Gateway identity and mutual authentication

- Each gateway holds an **Ed25519 identity key** (runtime-only, invariant 12),
  distinct from its ledger event-chain signing key. The identity key signs
  wire messages; the chain key signs the local event chain. Splitting them
  means a leaked chain key does not impersonate the gateway on the wire, and
  vice versa.
- Trust is **pre-shared at setup**: a gateway is configured with the peer's
  identity **public key** (and its identity id, a ULID). This is the
  SSH-known-hosts model, not a PKI — there is no certificate infrastructure
  in v0.1.
- **Mutual authentication** = two independent facts checked on every inbound
  message: (a) the sender's identity is registered on this gateway, and (b)
  the message verifies against that registered public key. Either failure
  rejects the message before any processing. There is no "anonymous but
  logged" path: unregistered senders get no state side effect.
- The deal's mandate already names its counterparty: the registered peer's
  identity id is the `counterparty_id` on the `AuthorityRecord`. A wire
  `proposal` for a deal whose audience is another gateway is therefore
  accepted **only** from that gateway — the engine's existing step 5 check
  does the rest. No new domain field.

### Message envelope

- The wire format is a JSON envelope, versioned, signed over its canonical
  form (`crypto/canonicalization.py`, invariant 13):

  | field | meaning |
  |---|---|
  | `schema_version` | pinned to `"0.1"`; a different value is rejected (no negotiation, ADR-0004 precedent) |
  | `message_id` | ULID, sender-assigned; identifies the message |
  | `idempotency_key` | ULID, sender-assigned; the replay key (ADR-0007, wire level) |
  | `sender_id` | sender's identity ULID (must match the key that signed) |
  | `recipient_id` | receiver's identity ULID (must match this gateway) |
  | `kind` | one of `proposal`, `counterparty_event`, `receipt` |
  | `payload` | kind-specific object (below) |
  | `issued_at` | RFC 3339 timestamp |
  | `signature` | `{algorithm: "Ed25519", key_id, value}` over the canonical form of everything above except `signature` |

- **Message kinds and payloads:**
  - `proposal` — a `PolicyInput`-shaped proposal from the sender's agent.
    Untrusted (invariant 1): the receiver parses it into its own domain
    models and runs it through `process_request` exactly like local input.
    The envelope authenticates *which gateway* proposed it; it does not
    authorize the action.
  - `counterparty_event` — a boundary/counterparty event (e.g. the customer
    gateway recording `quote_received`). The receiver commits it as a
    counterparty event; the sender must be the deal's registered
    counterparty identity.
  - `receipt` — the receiver's answer to one of the above: the
    `message_id` it answers, the outcome, the local event ids, and its own
    signature. A receipt is a first-class signed artifact (invariant 15);
    the sender can independently verify it.
- Cross-message non-transfer applies: a signature valid on one envelope is
  invalid on any other (same test family as `test_signing.py`).

### Delivery

- **Synchronous REST push**: `POST /messages` on each gateway. The pipeline
  is verify-first, in order: size/shape → `schema_version` → recipient match
  → sender registered → signature → idempotency → kind dispatch →
  `process_request` / counterparty commit → signed receipt. Each stage that
  fails returns a structured error (4xx) and commits nothing.
- The response is a JSON body carrying the signed receipt (or the structured
  rejection). There is no async queue, no background worker, no push from
  server to client in v0.1.
- **The peer endpoint has no operator auth.** ADR-0011's login/CSRF protect
  the *console*; the wire's authentication is the message signature itself.
  Rejecting garbage before processing is the mitigation for the fact that
  this endpoint is reachable without a session.

### Idempotency (invariant 14, ADR-0007 at wire level)

- Each gateway keeps an **idempotency store** keyed by
  `(sender_id, idempotency_key)`, recording the stored receipt (or rejection)
  plus a digest of the envelope that produced it.
- Redelivery of the same envelope returns the **stored** answer — no
  reprocessing, no duplicate events.
- The same `(sender_id, idempotency_key)` with a **different** envelope is
  hostile, not a typo: rejected, logged, no state change (ADR-0007's rule,
  verbatim).
- In-memory for the local test setup; a Postgres `message_dedup` table
  (migration 0003) for durability across restarts.

### "Separate machines" in v0.1

- The claim being proven is **independent gateways**: two processes, two
  `AppState` instances, two ledgers, two key sets, communicating only through
  HTTP. Tests run both on one host, separate loopback ports; true network
  isolation is a deployment detail and is documented as such, not faked.
- **No TLS in v0.1** (ADR-0011's limitation carries over): the loopback
  default keeps the wire local; a non-loopback bind is configurable for a
  real two-host setup and is a documented risk (an on-path host can see
  message *structure* but cannot forge or modify a message — signatures are
  end-to-end; payloads are **not** encrypted).

## Consequences

- New package `src/mandate/transport/`: `envelope.py` (model, canonical
  form, sign/verify — pure, no I/O, invariant 2), `dedup.py` (idempotency
  store, in-memory + Postgres), `gateway.py` (app factory + pipeline).
- `api/` (the console) is untouched; the gateway is a second app factory in
  the boundary. `transport/` may import `api/`-level things only via
  `application/` and `crypto/`; the pure layers stay I/O-free (banned-import
  scan extended to `transport/`).
- Postgres: `message_dedup` table + Alembic migration 0003.
- Keys: identity keys are runtime-only, generated by a `dev_keys`-style
  script; the peer's public key is supplied at gateway startup (env /
  `.dev/` file), never in source.
- **Out of scope for v0.1:** A2A Agent Cards and task lifecycle (Phase 9 —
  the REST envelope is deliberately adapter-shaped so A2A wraps it later),
  async queues / workers, TLS and mTLS, PKI/certificates, rate limiting
  (Deferred, ADR-0011 precedent), payload encryption, multi-host deployment
  tooling (docker-compose etc.).
- Tests pin: envelope canonical determinism + tamper + wrong-key +
  algorithm-spoof + cross-message non-transfer; unregistered sender → 4xx,
  no state; replay → stored answer, zero new events; key reuse with a
  different payload → hostile rejection; `schema_version` mismatch →
  rejected; two-gateway end-to-end deal over real HTTP with both ledgers
  independently `verify_chain`-clean; receipt independently verifiable by
  the sender.
