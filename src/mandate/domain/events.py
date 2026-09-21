"""Event ledger event model (brief §13, ADR-0009).

Frozen. Two stored hashes, both validated at construction so an inconsistent
event is unconstructible:

- ``payload_hash`` = SHA-256 of the canonical bytes of ``payload``;
- ``event_hash``   = SHA-256 of the canonical event form — every field except
  ``signature`` and ``event_hash``. The Ed25519 signature covers exactly
  those bytes (invariant 13).
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from mandate.crypto.canonicalization import canonical_bytes, canonical_sha256_hex
from mandate.domain.authority import _validate_ulid
from mandate.domain.input import ActorKind

GENESIS_HASH = "0" * 64

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class EventType(StrEnum):
    """Seven-type vocabulary (brief §13): the six ADR-0009 types plus
    `REVOCATION`, the schema 0.2 extension (ADR-0014)."""

    POLICY_DECISION = "policy_decision"
    STATE_TRANSITION = "state_transition"
    APPROVAL = "approval"
    MESSAGE = "message"
    ARTIFACT = "artifact"
    PAYMENT = "payment"
    REVOCATION = "revocation"


class EventSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str
    key_id: str
    value: str


def _validate_hash(v: str) -> str:
    if not _HASH_RE.match(v):
        msg = f"not a 64-char lowercase hex hash: {v!r}"
        raise ValueError(msg)
    return v


def event_canonical_form(event: Event) -> dict[str, object]:
    """The canonical event form: all fields except ``signature`` and
    ``event_hash`` (ADR-0009). Keys are sorted by the canonicalizer."""
    data = event.model_dump(mode="json")
    data.pop("signature", None)
    data.pop("event_hash", None)
    return data


def event_signing_bytes(event: Event) -> bytes:
    """The exact bytes hashed into ``event_hash`` and covered by the
    signature."""
    return canonical_bytes(event_canonical_form(event))


class Event(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    deal_id: str
    sequence_number: int
    event_type: EventType
    actor_kind: ActorKind
    actor_id: str
    authority_record_id: str | None
    previous_event_hash: str
    payload_hash: str
    event_hash: str
    payload: dict[str, object]
    occurred_at: str
    recorded_at: str
    signature: EventSignature

    _v_event_id = field_validator("event_id")(_validate_ulid)
    _v_deal_id = field_validator("deal_id")(_validate_ulid)
    _v_prev = field_validator("previous_event_hash")(_validate_hash)
    _v_payload_hash = field_validator("payload_hash")(_validate_hash)
    _v_event_hash = field_validator("event_hash")(_validate_hash)

    @field_validator("sequence_number")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            msg = f"sequence_number must be >= 0, got {v}"
            raise ValueError(msg)
        return v

    @field_validator("authority_record_id")
    @classmethod
    def _v_record_ref(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v

    @model_validator(mode="after")
    def _check_hashes(self) -> Event:
        if self.payload_hash != canonical_sha256_hex(self.payload):
            msg = "payload_hash does not match the canonical payload"
            raise ValueError(msg)
        if self.event_hash != canonical_sha256_hex(event_canonical_form(self)):
            msg = "event_hash does not match the canonical event form"
            raise ValueError(msg)
        return self
