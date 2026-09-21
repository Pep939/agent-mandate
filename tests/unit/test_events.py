"""Unit tests for the Event model (brief §13, ADR-0009)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mandate.domain.events import (
    GENESIS_HASH,
    Event,
    EventSignature,
    EventType,
    event_canonical_form,
    event_signing_bytes,
)
from mandate.domain.input import ActorKind
from mandate.ledger.chain import build_event
from tests.support.factories import (
    NOW,
    make_signer,
    new_ulid,
)


def _base_event(**overrides):
    signer = make_signer()
    defaults = {
        "event_id": new_ulid(),
        "deal_id": new_ulid(),
        "sequence_number": 0,
        "event_type": EventType.POLICY_DECISION,
        "actor_kind": ActorKind.AGENT,
        "actor_id": new_ulid(),
        "authority_record_id": None,
        "previous_event_hash": GENESIS_HASH,
        "payload": {"k": "v"},
        "occurred_at": NOW,
        "recorded_at": NOW,
        "signer": signer,
    }
    defaults.update(overrides)
    return build_event(**defaults)


class TestConstruction:
    def test_valid_event_round_trips(self):
        event = _base_event()
        assert event.event_hash
        assert event.payload_hash
        assert event.signature.value

    def test_genesis_is_64_zero_hex(self):
        assert GENESIS_HASH == "0" * 64


class TestPayloadHashValidation:
    def test_mismatched_payload_hash_rejected(self):
        event = _base_event()
        with pytest.raises(ValidationError):
            Event(**{**event.model_dump(), "payload_hash": "ab" * 32})

    def test_payload_hash_matches_canonical_payload(self):
        event = _base_event(payload={"a": 1, "b": [1, 2, 3]})
        from mandate.crypto.canonicalization import canonical_sha256_hex

        assert event.payload_hash == canonical_sha256_hex(event.payload)


class TestEventHashValidation:
    def test_mismatched_event_hash_rejected(self):
        event = _base_event()
        with pytest.raises(ValidationError):
            Event(**{**event.model_dump(), "event_hash": "cd" * 32})

    def test_event_hash_excludes_signature_and_event_hash(self):
        event = _base_event()
        form = event_canonical_form(event)
        assert "signature" not in form
        assert "event_hash" not in form
        assert "event_id" in form
        from mandate.crypto.canonicalization import canonical_sha256_hex

        assert event.event_hash == canonical_sha256_hex(form)


class TestEventSigningBytes:
    def test_signing_bytes_are_deterministic(self):
        event = _base_event()
        assert event_signing_bytes(event) == event_signing_bytes(event)

    def test_reordering_payload_keys_does_not_change_hash(self):
        e1 = _base_event(payload={"a": 1, "b": 2})
        e2 = _base_event(payload={"b": 2, "a": 1})
        # same logical payload → same payload_hash
        assert e1.payload_hash == e2.payload_hash


class TestEventIdAndSequence:
    def test_negative_sequence_rejected(self):
        with pytest.raises(ValidationError):
            Event(
                event_id=new_ulid(),
                deal_id=new_ulid(),
                sequence_number=-1,
                event_type=EventType.POLICY_DECISION,
                actor_kind=ActorKind.AGENT,
                actor_id=new_ulid(),
                authority_record_id=None,
                previous_event_hash=GENESIS_HASH,
                payload_hash="ab" * 32,
                event_hash="cd" * 32,
                payload={},
                occurred_at=NOW,
                recorded_at=NOW,
                signature=EventSignature(algorithm="Ed25519", key_id="k", value="v"),
            )

    def test_bad_previous_hash_rejected(self):
        with pytest.raises(ValidationError):
            _base_event(previous_event_hash="zz")
