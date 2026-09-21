"""Unit tests for evidence bundles (specs/evidence-bundle.md)."""

from __future__ import annotations

import hashlib
import json

from mandate.application.services import process_request
from mandate.crypto.canonicalization import canonical_bytes, canonical_sha256_hex
from mandate.domain.authority import Revocation, SignatureBlock
from mandate.domain.deals import DealState
from mandate.ledger.evidence import (
    SCHEMA_VERSION,
    build_bundle,
    bundle_json,
    render_checksums,
    render_timeline,
    summary_signing_bytes,
    verify_bundle,
)
from mandate.ledger.store import InMemoryLedgerStore
from tests.support.factories import (
    NOW,
    PAST,
    make_deal,
    make_input,
    make_proposal,
    make_signer,
    new_ulid,
)

RECORDED = "2026-01-15T12:00:01Z"


def _seeded():
    store = InMemoryLedgerStore()
    deal = make_deal(state=DealState.DRAFT)
    store.create_deal(deal, PAST)
    signer = make_signer()
    pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id, action="request_quote"))
    process_request(pi, store, signer, recorded_at=RECORDED)
    current = store.get_deal(deal.deal_id)
    assert current is not None
    return store, deal, current, signer, pi


def _revocation(record_id: str) -> Revocation:
    return Revocation(
        schema_version="0.1",
        revocation_id=new_ulid(),
        record_id=record_id,
        revoked_at=NOW,
        signature=SignatureBlock(algorithm="ed25519", key_id="k", value="v"),
    )


class TestBuildBundle:
    def test_summary_binds_all_sections(self):
        store, deal, current, signer, pi = _seeded()
        rec = pi.authority.record
        rev = _revocation(rec.record_id)
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[rec],
            revocations=[rev],
            signer=signer,
        )
        assert bundle.schema_version == SCHEMA_VERSION
        v = bundle.verification
        assert v.event_count == len(bundle.events)
        assert v.chain_sha256 == canonical_sha256_hex(
            [e.model_dump(mode="json") for e in bundle.events]
        )
        assert v.records_sha256 == canonical_sha256_hex([rec.model_dump(mode="json")])
        assert v.revocations_sha256 == canonical_sha256_hex([rev.model_dump(mode="json")])
        assert v.chain_head_event_hash == bundle.events[-1].event_hash

    def test_empty_chain_uses_genesis_head(self):
        signer = make_signer()
        empty = make_deal(state=DealState.DRAFT, deal_id=new_ulid())
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=empty,
            deal_created_at=PAST,
            events=[],
            records=[],
            revocations=[],
            signer=signer,
        )
        assert bundle.verification.chain_head_event_hash == "0" * 64
        assert bundle.verification.event_count == 0
        assert verify_bundle(bundle).ok

    def test_gateway_public_key_round_trips(self):
        from mandate.crypto.signing import b64url_decode, load_public_key

        store, deal, current, signer2, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer2,
        )
        key = load_public_key(b64url_decode(bundle.gateway_public_key.key_b64url))
        assert key == signer2.public_key


class TestBundleJson:
    def test_is_canonical_and_stable(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        text = bundle_json(bundle)
        assert text == canonical_bytes(bundle.model_dump(mode="json")).decode("ascii")
        # parses back to the same bundle
        from mandate.ledger.evidence import EvidenceBundle

        assert EvidenceBundle.model_validate(json.loads(text)) == bundle

    def test_checksums_match_files(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        lines = render_checksums(bundle).splitlines()
        assert len(lines) == 2
        bundle_hash, name = lines[0].split("  ")
        assert name == "bundle.json"
        assert bundle_hash == hashlib.sha256(bundle_json(bundle).encode()).hexdigest()


class TestRenderTimeline:
    def test_one_line_per_event(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        timeline = render_timeline(bundle)
        assert f"deal {deal.deal_id}" in timeline
        rows = [
            line
            for line in timeline.splitlines()
            if line.startswith("| 0 ") or line.startswith("| 1 ")
        ]
        assert len(rows) == len(bundle.events)
        assert "policy_decision" in timeline
        assert "state_transition" in timeline


class TestVerifyBundle:
    def test_deal_state_divergence_detected(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        lie = bundle.model_copy(
            update={"deal": bundle.deal.model_copy(update={"state": "CANCELLED"})}
        )
        report = verify_bundle(lie)
        assert not report.ok
        assert any(c.name == "deal_state_divergent" and not c.ok for c in report.checks)

    def test_wrong_schema_version_detected(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        bad = bundle.model_copy(update={"schema_version": "9.9"})
        report = verify_bundle(bad)
        assert not report.ok
        assert any(c.name == "schema_version" and not c.ok for c in report.checks)

    def test_truncated_events_detected_by_summary(self):
        store, deal, current, signer, pi = _seeded()
        events = store.events_for(deal.deal_id)
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=events,
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        # a raw truncation is self-consistent; the summary is the witness.
        # (The summary signature still matches the unchanged summary here —
        # it is the witness for the re-export case, see test_tamper.py
        # TestSuiteC_EvidenceBundleTamper.)
        truncated = bundle.model_copy(update={"events": events[:1]})
        report = verify_bundle(truncated)
        assert not report.ok
        names = {c.name for c in report.checks if not c.ok}
        assert "event_count" in names and "chain_sha256" in names


class TestSummarySignature:
    def test_genuine_signature_verifies(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        report = verify_bundle(bundle)
        assert any(c.name == "summary_signature" and c.ok for c in report.checks)

    def test_signature_by_different_key_fails(self):
        from mandate.crypto.signing import ALGORITHM

        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        forger = make_signer()
        forged = bundle.model_copy(
            update={
                "summary_signature": SignatureBlock(
                    algorithm=ALGORITHM,
                    key_id=forger.key_id,
                    value=forger.sign_bytes(
                        summary_signing_bytes(
                            deal_id=deal.deal_id,
                            key_id=forger.key_id,
                            summary=bundle.verification,
                        )
                    ),
                )
            }
        )
        report = verify_bundle(forged)
        assert not report.ok
        assert any(c.name == "summary_signature" and not c.ok for c in report.checks)

    def test_signature_key_id_mismatch_fails(self):
        store, deal, current, signer, pi = _seeded()
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=current,
            deal_created_at=PAST,
            events=store.events_for(deal.deal_id),
            records=[pi.authority.record],
            revocations=[],
            signer=signer,
        )
        lie = bundle.model_copy(
            update={
                "summary_signature": bundle.summary_signature.model_copy(
                    update={"key_id": "another-key"}
                )
            }
        )
        report = verify_bundle(lie)
        assert not report.ok
        assert any(c.name == "summary_signature" and not c.ok for c in report.checks)
