# ADR-0005: Ed25519 via `cryptography`; runtime-only key material

Status: accepted (2026-09-01, maintainer approval of the Phase 2 breakdown)

## Context

Phase 2 introduces signing (brief §16). Brief §7 allows "Ed25519 via PyNaCl or
`cryptography`". Invariant 12 forbids signing keys and secrets in prompts, logs,
events, fixtures, client HTML or source control.

## Decisions

- **Library:** `cryptography` (Ed25519). Standard, actively maintained, no C
  dependency beyond what the project already avoids — chosen over PyNaCl for
  longevity and ecosystem fit.
- **Algorithm string:** exactly `"Ed25519"` in `SignatureBlock.algorithm`.
  Signatures are base64url-encoded raw 64-byte Ed25519 signatures.
- **Key IDs:** ULIDs, consistent with every other identity in the system.
- **Signed payload:** the canonical authority record **excluding** the
  `signature` field (per `specs/authority-envelope.md`). Canonical form is the
  single implementation in `src/mandate/crypto/canonicalization.py`, shared by
  record signing and the policy engine's `input_digest` — one canonical JSON
  algorithm for the whole product (invariant 13).
- **Key material never lives in the repo.** Dev keys are generated at runtime by
  `scripts/dev_keys.py` into gitignored `.dev/keys/`. Tests generate ephemeral
  keys in memory. No key bytes, seeds or derived values appear in fixtures,
  golden vectors, logs or source.
- **Timestamps:** model validators normalize RFC3339 timestamps to UTC `Z`
  form at construction, so canonical bytes are stable per the envelope spec.

## Consequences

- `crypto/` stays pure (no I/O); key file I/O lives only in the dev script.
  The banned-imports AST scan covers `crypto/`.
- The engine's `input_digest` bytes change value when it switches to the shared
  canonicalizer. No consumer pins exact digest values in v0.1; determinism is
  what the invariants require.
- Production key custody (HSM, rotation, custody UX) is deliberately out of
  scope until Phase 4+ (brief §16); dev keys are a development convenience, not
  a production path.
