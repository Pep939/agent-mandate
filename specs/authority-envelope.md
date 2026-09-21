# Spec: Authority Record (envelope) v0.1

Status: FINAL for v0.1 (2026-08-31). Refines brief §10. Resolved modeling choices
are cross-referenced to `docs/decisions/ADR-0004-v01-spec-defaults.md`.

An **authority record** describes *permission*; it does not itself prove that an
action occurred (brief §10). Proof of occurrence is the event ledger.

## Record schema

```yaml
schema_version: "0.1"
record_id: "ULID"
principal_id: "ULID, the owner whose authority this is"
agent_id: "ULID, the authorized agent instance"
counterparty_id: "ULID or null, optional audience restriction"
purpose: "human-readable purpose (plain sentence)"
allowed_actions: []        # tokens from the closed action vocabulary (policy-schema §Action vocabulary)
prohibited_actions: []     # same vocabulary; beats allowed_actions (invariant 6)
spend_cap:
  currency: "ISO-4217, e.g. USD"
  amount_minor: int        # integer minor units, never float
max_negotiation_rounds: int
acceptance_window_hours: int
silent_acceptance: false   # A1: timeout-acceptance flag, default off
disclosure_fields: []      # field tokens the agent may expose (allow-list, invariant 9)
requires_human_approval_for: []  # action tokens; see Approval semantics
issued_at: "RFC3339"
not_before: "RFC3339"
expires_at: "RFC3339"
parent_record_id: "ULID or null, delegation chain"
status: "active|revoked|expired"
nonce: "unique anti-replay value"
signature:
  algorithm: "Ed25519"
  key_id: "owner signing key ID"
  value: "base64url signature over canonical payload"
```

## Field rules

- **Money:** `amount_minor` is an integer in the cap's currency's minor unit
  (e.g. cents for USD). Single currency per record. Floats are a validation
  error (invariant, money-as-integer).
- **Schema versioning:** `schema_version` is required and semver-ish (`0.1`).
  Unknown major versions are rejected at parse (`unknown_schema_version`).
  Migrations are forward-only and versioned.
- **Identity vs credentials:** `principal_id` / `agent_id` are *identities*
  (ULIDs), not authentication credentials. Authentication is the signature and
  the boundary's verification claim, kept separate (brief §10).
- **Validity interval:** `not_before <= now <= expires_at` must hold; the
  boundary supplies `now` (A8) — the record never reads a clock itself.
  AMBIGUITY carried from brief §23 (clock skew): handled by the boundary as a
  trusted timestamp; the domain treats it as exact. Skew tolerance is a
  boundary/deployment concern, not a domain rule.
- **Anti-replay:** `nonce` (per record) + `request_id` (per proposal) +
  `idempotency_key` (per action) + audience/counterparty restriction + validity
  interval together form the replay defense.
- **Delegation chain:** `parent_record_id` links a child record to its parent.
  A child's scope must be a **subset** of the parent's (narrowing only).
  Revoking a parent revokes all descendants (invariant 7). Max depth is an open
  question (brief §23) — proposed: **no default limit in v0.1**, but the chain
  must be acyclic and fully resolvable; record it in an ADR if a limit is set.

## Status lifecycle

```text
active ──(revoke, signed)──> revoked
active ──(now > expires_at)──> expired
```

- `revoked` and `expired` are terminal and take effect immediately (invariant 7).
- `status` is *resolved by the boundary* at evaluation time and passed into
  `PolicyInput` as a claim; the domain does not recompute it from the clock.

## Canonical serialization (invariant 13)

- A deterministic canonical JSON form is defined for signing (sorted keys, no
  whitespace, explicit string encoding, integer money, no floats, stable
  RFC3339 `Z` timestamps).
- The signature covers the canonical payload **excluding** the `signature` field
  itself.
- Signing and verification must reproduce identical bytes (property test).
- Exact canonicalization algorithm is specified in Phase 2 (`src/mandate/crypto/
  canonicalization.py`) — v0.1/Phase 1 does not sign; it only models the record.

## What the record is NOT

- Not a legal contract (brief §2).
- Not proof an action happened (that's the ledger).
- Not a credential or an authentication token (that's identity + signature).
