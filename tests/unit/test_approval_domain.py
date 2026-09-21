"""Unit tests for the signed one-time approval override (ADR-0010).

Covers the sign/verify roundtrip (invariant 13: deterministic canonical
serialization reproduces identical bytes) and tamper detection (invariant 15).
"""

from __future__ import annotations

from mandate.crypto.canonicalization import approval_signing_payload
from mandate.crypto.signing import b64url_decode, make_approval_record
from mandate.crypto.verification import verify_approval
from mandate.domain.approvals import ApprovalRecord
from tests.support.factories import NOW, make_signer, new_ulid


def _record(**overrides):
    defaults = {
        "approval_record_id": new_ulid(),
        "deal_id": new_ulid(),
        "request_id": new_ulid(),
        "parent_authority_record_id": new_ulid(),
        "action": "accept_agreement",
        "amount_minor": 10**9,
        "currency": "USD",
        "proposal_digest": "0" * 64,
        "issued_at": NOW,
    }
    defaults.update(overrides)
    signer = make_signer()
    return signer, make_approval_record(signer=signer, **defaults)


class TestMakeApprovalRecord:
    def test_signature_covers_canonical_payload(self):
        signer, record = _record()
        # the raw signature verifies over the canonical payload bytes
        raw = b64url_decode(record.signature.value)
        signer.public_key.verify(raw, approval_signing_payload(record))

    def test_field_defaults(self):
        _, record = _record()
        assert record.schema_version == "0.1"
        assert record.signature.key_id == "test-gateway-key"


class TestVerifyApproval:
    def test_verify_roundtrip(self):
        signer, record = _record()
        result = verify_approval(record, signer.public_key)
        assert result.valid is True

    def test_wrong_key_fails(self):
        _, record = _record()
        other = make_signer()
        assert verify_approval(record, other.public_key).valid is False

    def test_tampered_amount_fails(self):
        signer, record = _record()
        tampered = record.model_copy(update={"amount_minor": 1})
        assert verify_approval(tampered, signer.public_key).valid is False

    def test_tampered_action_fails(self):
        signer, record = _record()
        tampered = record.model_copy(update={"action": "cancel_deal"})
        assert verify_approval(tampered, signer.public_key).valid is False

    def test_tampered_proposal_digest_fails(self):
        signer, record = _record()
        tampered = record.model_copy(update={"proposal_digest": "1" * 64})
        assert verify_approval(tampered, signer.public_key).valid is False

    def test_tampered_parent_fails(self):
        signer, record = _record()
        tampered = record.model_copy(update={"parent_authority_record_id": new_ulid()})
        assert verify_approval(tampered, signer.public_key).valid is False

    def test_expected_key_id_mismatch(self):
        signer, record = _record()
        result = verify_approval(record, signer.public_key, expected_key_id="someone-else")
        assert result.valid is False


class TestCanonicalizationStability:
    def test_payload_excludes_signature(self):
        _, record = _record()
        # changing only the signature must not change the canonical payload
        dumped = record.model_dump(mode="json")
        dumped["signature"] = {
            **dumped["signature"],
            "value": "different",
        }
        changed = ApprovalRecord.model_validate(dumped)
        assert approval_signing_payload(record) == approval_signing_payload(changed)
