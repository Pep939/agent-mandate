# ADR-0015: Signed evidence-bundle summary (schema 0.2) — the head-hash anchor

Status: accepted (2026-09-07, builder executing the maintainer's 2026-09-07
instruction to take the next item; external review pending).

## Context

The external audit of 2026-09-04 found (A2 #7, MED):

> The bundle's summary is hashes only, unsigned. An attacker with database
> access can truncate the tail of the event chain and re-export the bundle;
> the re-export recomputes the summary hashes, so every check passes and the
> bundle is "clean".

The bundle verifies everything about each event (payload hash, event hash,
signature, sequence, chain link), and the summary binds the event *list*
(`event_count`, `chain_sha256`, `chain_head_event_hash`) plus the
records/revocations sections. But the summary itself is produced by whoever
runs the export. The spec's promise — "anyone who receives the files can
verify the full decision history **without** the original database" — was
therefore conditional on trusting the exporter not to truncate.

That condition is removable with a key we already hold. ADR-0014 decision 4
fixed v0.1 key custody: one persisted keypair per gateway, whose **chain
key** signs every event on the ledger. A re-exporter with database access
does not have that key — it lives in the gateway's custody (C1), not in the
database.

## Decisions

### 1. The summary is signed by the gateway's chain signer

`EvidenceBundle` gains `summary_signature: SignatureBlock`. The payload is
`summary_signing_bytes` — canonical serialization (invariant 13) of
`{"kind": "mandate.evidence-summary", "schema_version", "deal_id", "key_id",
"verification": <the verification summary>}` — binding the head hash, event
count and section hashes to the deal and the signing key. `kind` prevents
cross-payload forgery with other signed objects (invariant 13).

### 2. `build_bundle` requires the signer

`build_bundle(..., signer: GatewaySigner)` replaces the old
`public_key: GatewayPublicKeyRef` parameter: a valid bundle cannot be built
without the private key, and `gateway_public_key` in the output is derived
from the signer. `scripts/export_evidence.py` takes `--chain-key` (the
gateway's chain-signer key file) instead of `--public-key`/`--key-id`.
Call sites: `dev_seed.py`, `export_evidence.py`, tests.

### 3. `verify_bundle` gains the `summary_signature` check

After the summary-hash checks: the signature's `algorithm` is `Ed25519`, its
`key_id` equals `gateway_public_key.key_id`, and the gateway key verifies it
over `summary_signing_bytes` recomputed from the bundle's **current**
summary. The check runs only when the public key loads, mirroring the event
checks. A failure names `summary_signature` — the re-exporter's recomputed
summary is exactly the payload they cannot sign.

### 4. The schema is versioned 0.1 → 0.2

Bundles without the field fail `schema_version`; there is no silent
compatibility path (invariant 13: schema changes are versioned, never ad
hoc). All bundles in the tree are generated at export time, so no static 0.1
fixture exists to migrate.

### 5. The trust boundary is stated

The summary signature binds the summary to the gateway's chain key. An
attacker who **holds the chain key** can sign a truncated summary — but that
attacker holds the root of trust for every event on the ledger as well, and
no bundle format can do better than the key it is anchored to. External
anchoring (on-chain anchor, third-party timestamping) is out of scope for
v0.1 (spec, "Out of scope").

## Consequences

- Exporting a bundle now requires the chain key. This is correct by design:
  the gateway is the only party that should produce bundles for its ledger;
  a recipient verifies with the public key alone.
- `verify_bundle` reports one more check per bundle (e.g. 18/18 for a
  2-event deal; 133/133 for the `dev_seed` full lifecycle).
- New tests: `TestSummarySignature` (genuine verifies; foreign-key signature
  fails; key_id mismatch fails) and the decisive tamper test — a re-exported
  truncation fails with `{summary_signature}` as the **only** failing check
  (every hash check passes on the forged bundle). Verified live: seeded a
  deal in Postgres, exported via the new CLI, replayed the attack on the
  real export.
- `verify_chain` (the in-ledger path) is unchanged; its docstring now points
  to the signed summary as the witness for post-export truncation.
