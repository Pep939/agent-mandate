"""Unit tests for the shared canonical serialization (invariant 13)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mandate.crypto.canonicalization import canonical_bytes, record_signing_payload
from mandate.domain.authority import (
    ActionToken,
    AuthorityRecord,
    RecordStatus,
    SignatureBlock,
    SpendCap,
)
from tests.support.factories import make_record

GOLDEN_RECORD = AuthorityRecord(
    schema_version="0.1",
    record_id="0123456789ABCDEF0123456789",
    principal_id="01234567890123456789012345",
    agent_id="01234567890123456789012346",
    counterparty_id=None,
    purpose="golden vector record",
    allowed_actions=[ActionToken.REQUEST_QUOTE, ActionToken.ACCEPT_AGREEMENT],
    prohibited_actions=[ActionToken.CAPTURE_PAYMENT],
    spend_cap=SpendCap(currency="USD", amount_minor=250000),
    max_negotiation_rounds=3,
    acceptance_window_hours=24,
    silent_acceptance=False,
    disclosure_fields=["work_order_id"],
    requires_human_approval_for=[ActionToken.CAPTURE_PAYMENT],
    issued_at="2026-01-01T00:00:00Z",
    not_before="2026-01-02T00:00:00Z",
    expires_at="2026-02-01T00:00:00Z",
    parent_record_id=None,
    status=RecordStatus.ACTIVE,
    nonce="01234567890123456789012347",
    signature=SignatureBlock(
        algorithm="Ed25519", key_id="01234567890123456789012348", value="placeholder"
    ),
)

GOLDEN_PAYLOAD_HEX = (
    "7b22616363657074616e63655f77696e646f775f686f757273223a32342c226167656e745f6964223a22303132333435363738393031"
    "3233343536373839303132333436222c22616c6c6f7765645f616374696f6e73223a5b22726571756573745f71756f7465222c2261"
    "63636570745f61677265656d656e74225d2c22636f756e74657270617274795f6964223a6e756c6c2c22646973636c6f737572655f"
    "6669656c6473223a5b22776f726b5f6f726465725f6964225d2c22657870697265735f6174223a22323032362d30322d30315430"
    "303a30303a30305a222c226973737565645f6174223a22323032362d30312d30315430303a30303a30305a222c226d61785f6e6"
    "5676f74696174696f6e5f726f756e6473223a332c226e6f6e6365223a223031323334353637383930313233343536373839303132"
    "333437222c226e6f745f6265666f7265223a22323032362d30312d30325430303a30303a30305a222c22706172656e745f726563"
    "6f72645f6964223a6e756c6c2c227072696e636970616c5f6964223a22303132333435363738393031323334353637383930313233"
    "3435222c2270726f686962697465645f616374696f6e73223a5b22636170747572655f7061796d656e74225d2c22707572706f7365"
    "223a22676f6c64656e20766563746f72207265636f7264222c227265636f72645f6964223a22303132333435363738394142434445"
    "4630313233343536373839222c2272657175697265735f68756d616e5f617070726f76616c5f666f72223a5b22636170747572655f"
    "7061796d656e74225d2c22736368656d615f76657273696f6e223a22302e31222c2273696c656e745f616363657074616e636522"
    "3a66616c73652c227370656e645f636170223a7b22616d6f756e745f6d696e6f72223a3235303030302c2263757272656e6379223a"
    "22555344227d2c22737461747573223a22616374697665227d"
)


def test_golden_record_payload_is_byte_stable():
    """Known vector: the canonical payload of a fixed record is pinned.

    Any change to the canonicalization algorithm fails here on purpose
    (invariant 13: signing and verification must reproduce identical bytes).
    """
    assert record_signing_payload(GOLDEN_RECORD).hex() == GOLDEN_PAYLOAD_HEX


def test_signature_field_is_excluded_from_payload():
    other = GOLDEN_RECORD.model_copy(
        update={
            "signature": SignatureBlock(
                algorithm="Ed25519", key_id="different-key", value="different-value"
            )
        }
    )
    assert record_signing_payload(other) == record_signing_payload(GOLDEN_RECORD)


def test_key_insertion_order_is_irrelevant():
    a = canonical_bytes({"z": 1, "a": {"y": 2, "b": 3}})
    b = canonical_bytes({"a": {"b": 3, "y": 2}, "z": 1})
    assert a == b


def test_non_ascii_is_escaped_to_pure_ascii_bytes():
    raw = canonical_bytes({"k": "café"})
    raw.decode("ascii")  # raises if any non-ASCII leaked through
    assert b"\\u00e9" in raw


def test_list_order_is_preserved():
    assert canonical_bytes({"a": [1, 2, 3]}) != canonical_bytes({"a": [3, 2, 1]})


def test_floats_are_rejected():
    with pytest.raises(ValueError, match="floats"):
        canonical_bytes({"amount": 1.5})
    with pytest.raises(ValueError, match="floats"):
        canonical_bytes([1, 2.0])


def test_nan_is_rejected():
    import math

    with pytest.raises(ValueError):
        canonical_bytes({"v": math.nan})


def test_timestamps_normalize_to_utc_z_at_construction():
    rec = make_record(issued_at="2026-01-01T02:00:00+02:00", expires_at="2026-02-01T00:00:00z")
    assert rec.issued_at == "2026-01-01T00:00:00Z"
    assert rec.expires_at == "2026-02-01T00:00:00Z"


def test_non_utc_offset_normalizes_to_equivalent_utc():
    rec = make_record(expires_at="2026-02-01T05:30:00+05:30")
    assert rec.expires_at == "2026-02-01T00:00:00Z"


def test_invalid_timestamps_rejected():
    for bad in ("2026-01-01", "2026-01-01T00:00:00", "not-a-time", "2026-13-01T00:00:00Z"):
        with pytest.raises(ValidationError):
            make_record(issued_at=bad)
