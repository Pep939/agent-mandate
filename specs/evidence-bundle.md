# Spec: Evidence bundle (v0.1, schema 0.2)

A portable, independently verifiable evidence bundle for one deal. Anyone who
receives the files can verify the full decision history **without** the
original database, using only the gateway's public key.

Since schema 0.2 (ADR-0015) the summary is additionally **signed** by the
gateway's chain signer. The signature is the head-hash anchor: a re-exporter
with database access who truncates the tail and recomputes the summary can
satisfy every hash check, but cannot produce a valid `summary_signature`
without the chain key (audit A2 #7).

## Files

An export is a directory (or zip) with exactly three files:

| file | content |
|---|---|
| `bundle.json` | machine-readable bundle (this spec) |
| `timeline.md` | human-readable timeline, one line per event |
| `checksums.sha256` | SHA-256 of `bundle.json` and `timeline.md` |

## `bundle.json` schema (0.2)

```yaml
schema_version: "0.2"
exported_at: "RFC3339 UTC timestamp, boundary-supplied"
deal:                      # the stored deal row
  deal_id: "ULID"
  state: "DealState"
  negotiated_rounds: 0
  committed_minor: 0
  open_disputes: 0
  open_approvals: 0
  created_at: "RFC3339"
events: [Event, ...]       # ALL events of the deal, in sequence order (see below)
authority_records: [AuthorityRecord, ...]   # every record cited by an event, full canonical form
revocations: [Revocation, ...]              # every stored revocation of the above
gateway_public_key:        # verifies every event signature
  algorithm: "Ed25519"
  key_id: "ID"
  key_b64url: "32-byte raw public key, base64url"
verification:
  chain_head_event_hash: "event_hash of the final event (64 zeros if no events)"
  event_count: 0
  chain_sha256: "SHA-256 of canonical_bytes(events)"
  records_sha256: "SHA-256 of canonical_bytes(authority_records)"
  revocations_sha256: "SHA-256 of canonical_bytes(revocations)"
summary_signature:        # ADR-0015: anchors the verification summary
  algorithm: "Ed25519"
  key_id: "chain signer key_id; must equal gateway_public_key.key_id"
  value: "base64url Ed25519 signature over summary_signing_bytes(...)"
```

`summary_signing_bytes` is the canonical serialization of
`{"kind": "mandate.evidence-summary", "schema_version", "deal_id", "key_id",
"verification": <the verification summary>}` — the exact payload the gateway
chain signer signs at export time (`summary_signing_bytes`,
`src/mandate/ledger/evidence.py`).

`Event` is exactly the `mandate.domain.events.Event` model serialized with
`model_dump(mode="json")` — all fields, including `signature` and
`event_hash`. No field is omitted or renamed: the verifier recomputes from
what is present.

## Canonicalization and checksums

- Canonical bytes are produced by `mandate.crypto.canonicalization.canonical_bytes`
  (one algorithm, invariant 13).
- `chain_sha256` binds the entire event list in order.
- `checksums.sha256` is plain `sha256sum` output for the two files.

## Verification procedure (normative)

`verify_bundle` (pure, in `src/mandate/ledger/evidence.py`) and
`scripts/verify_ledger.py` (subprocess wrapper) both perform, in order.

**The verifying key is an input to the procedure, never a field of the
bundle.** `verify_bundle` takes a required `expected_key`, and
`verify_ledger.py` a required `--public-key`; the verifier obtains it out of
band from whatever its trust path is. This is not a detail. Verifying a
bundle against the key it carries proves only that the bundle is internally
consistent, which anyone can arrange by generating a keypair, signing a
fabricated chain and embedding the matching public key (issue #1, fixed
2026-09-21).

1. Parse `bundle.json`; reject unless `schema_version == "0.2"`
   (check `schema_version`).
2. Load `expected_key` (check `expected_public_key` if it is unusable), then
   compare `gateway_public_key.key_b64url` against it (check
   `gateway_public_key`). A mismatch is reported and verification continues
   against `expected_key`, so the event signatures below fail too — the
   report names both the wrong key and every signature it invalidates.
3. For each event, in listed order:
   a. recompute `payload_hash` = SHA-256 of canonical bytes of the stored
      `payload`; mismatch → fail `payload_hash_mismatch`;
   b. recompute `event_hash` over the canonical event form (all fields
      except `signature` and `event_hash`); mismatch → fail
      `event_hash_mismatch`;
   c. verify the Ed25519 `signature.value` over those exact bytes with the
      gateway key; failure → fail `event_signature_invalid`;
   d. check `sequence_number == index`; mismatch → fail `sequence_gap_or_swap`;
   e. check `previous_event_hash == GENESIS_HASH` for index 0, else equals
      the prior event's `event_hash`; mismatch → fail `chain_broken`.
4. Check `verification.event_count == len(events)` (check `event_count`) and
   `verification.chain_sha256 == SHA-256(canonical_bytes(events))` (check
   `chain_sha256`).
5. Check `verification.records_sha256` and `verification.revocations_sha256`
   against the recomputed section hashes (checks `records_sha256`,
   `revocations_sha256`).
6. Check `verification.chain_head_event_hash` equals the last event's
   `event_hash` (or `GENESIS_HASH` for an empty chain); mismatch → fail
   `chain_head_event_hash`.
7. Verify the signed summary (check `summary_signature`, ADR-0015):
   `summary_signature.algorithm` is `Ed25519`, `summary_signature.key_id`
   equals `gateway_public_key.key_id`, and the gateway key verifies
   `summary_signature.value` over the recomputed `summary_signing_bytes` for
   the **current** `verification` summary. Any mismatch → fail
   `summary_signature`. This is the check that defeats the re-exported
   truncation: the attacker's recomputed summary is exactly what they cannot
   sign.
8. Cross-check the deal row: the final `state_transition` event's `to_state`
   equals `deal.state`; mismatch → fail `deal_state_divergent`.

Result: `VerifyBundleReport(ok: bool, checks: list[CheckResult])` where each
`CheckResult` is `(name, ok, detail)`. The first failing check names the
likely tamper class (edit, delete, reorder, forge, summary swap).

## Guarantees (test suites C1–C3)

- **C1** — an unmodified bundle passes every check, in-process and
  out-of-process (`verify_ledger.py` exit 0).
- **C2** — a property test: any single-character mutation of `bundle.json`
  that parses as JSON and changes at least one event field fails with a
  named check.
- **C3** — swapping in a revocation of a different record fails
  (`event_signature_invalid` or `bundle_summary_mismatch` — the signature
  binds the payload, the summary binds the list).
- **C4** — a re-exported truncation (drop the tail, recompute the summary
  hashes) fails **only** on `summary_signature`: every hash check passes on
  the forged bundle, and the signature is the sole witness (audit A2 #7).

## Out of scope (v0.1)

- Bundles containing raw secrets: none exist in the ledger by design
  (ADR-0009; payloads carry digests, not material).
- Multi-deal bundles (one deal per bundle; export per deal).
- Signed agreement documents and payment-provider references appear in the
  bundle **only if** the corresponding `artifact`/`payment` events were
  recorded (brief §13 lists them; Phase 3 records no payment events, Phase 8
  does).
- External anchoring of the summary (on-chain anchor, third-party
  timestamping). v0.1 binds the summary to the gateway's chain key; the
  key-custody trust boundary is stated in ADR-0015.
