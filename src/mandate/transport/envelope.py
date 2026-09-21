"""The signed wire envelope (ADR-0012). Pure: no I/O (invariant 2).

Every message between gateways is a versioned JSON envelope signed with the
sender's identity key over its canonical form (invariant 13). The envelope
authenticates *which gateway* sent a message; it never authorizes anything —
a `proposal` payload only becomes a state change through the receiving
gateway's own policy engine (invariant 1).

Reuses the product's single canonical serializer and Ed25519 primitives
(ADR-0005). Cross-message non-transfer holds: a signature valid on one
envelope is invalid on any other.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator

from mandate.crypto.canonicalization import canonical_bytes
from mandate.crypto.signing import (
    ALGORITHM,
    b64url_decode,
    b64url_encode,
    load_private_key,
    load_public_key,
    public_key_raw,
    sign,
)
from mandate.domain.authority import (
    SignatureBlock,
    _validate_rfc3339,
    _validate_ulid,
    validate_amount_minor,
)

__all__ = [
    "SCHEMA_VERSION",
    "CounterpartyEventPayload",
    "EnvelopeError",
    "GatewayIdentity",
    "MessageKind",
    "ProposalPayload",
    "ReceiptOutcome",
    "ReceiptPayload",
    "WireEnvelope",
    "envelope_fingerprint",
    "envelope_is_stale",
    "envelope_signing_payload",
    "make_envelope",
    "parse_payload",
    "verify_envelope",
    "verify_receipt",
]

SCHEMA_VERSION = "0.1"


class EnvelopeError(ValueError):
    """A wire message failed a verify-first check. Carries the reason."""


class MessageKind(StrEnum):
    PROPOSAL = "proposal"
    COUNTERPARTY_EVENT = "counterparty_event"
    RECEIPT = "receipt"


class ReceiptOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class ProposalPayload(BaseModel):
    """The untrusted proposal part of a `proposal` message (invariant 1).

    Mirrors `domain.input.Proposal`; the receiver builds the full
    `PolicyInput` from its own stored record and deal — `authority` and
    `deal` never cross the wire.
    """

    model_config = ConfigDict(frozen=True)

    action: str
    deal_id: str
    amount_minor: int | None = None
    currency: str
    disclosure_fields: list[str] = []
    idempotency_key: str
    content: str = ""
    """The text the action would send (ADR-0016). Untrusted; the receiving
    gateway screens it and hands the engine only its digest + claims."""

    _v_deal_id = field_validator("deal_id")(_validate_ulid)
    _v_idempotency_key = field_validator("idempotency_key")(_validate_ulid)
    _v_amount_minor = field_validator("amount_minor")(validate_amount_minor)


MAX_NOTE_CHARS = 4096
"""Upper bound on a counterparty note. It is attacker-chosen text arriving off
the wire, and it was previously unbounded — a peer could hand over any volume of
it. The value is a boundary limit, not a domain rule: the note's digest is what
reaches an event (see `ledger.payloads.transition_payload`)."""


class CounterpartyEventPayload(BaseModel):
    """A boundary event from the peer gateway (e.g. `quote_received`)."""

    model_config = ConfigDict(frozen=True)

    deal_id: str
    event: str
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)

    _v_deal_id = field_validator("deal_id")(_validate_ulid)


class ReceiptPayload(BaseModel):
    """A receiver's answer to one message (ADR-0012: a first-class artifact)."""

    model_config = ConfigDict(frozen=True)

    responds_to: str
    outcome: ReceiptOutcome
    status: int
    events: list[str] = []
    reason: str | None = None
    decision: dict[str, Any] | None = None

    _v_responds_to = field_validator("responds_to")(_validate_ulid)


_PAYLOAD_MODELS: dict[MessageKind, type[BaseModel]] = {
    MessageKind.PROPOSAL: ProposalPayload,
    MessageKind.COUNTERPARTY_EVENT: CounterpartyEventPayload,
    MessageKind.RECEIPT: ReceiptPayload,
}


class WireEnvelope(BaseModel):
    """The signed wire message (ADR-0012 envelope schema)."""

    model_config = ConfigDict(frozen=True)

    schema_version: str
    message_id: str
    idempotency_key: str
    sender_id: str
    recipient_id: str
    kind: MessageKind
    payload: dict[str, Any]
    issued_at: str
    signature: SignatureBlock

    @field_validator("schema_version")
    @classmethod
    def _v_version(cls, v: str) -> str:
        if v != SCHEMA_VERSION:
            msg = f"unsupported envelope schema_version {v!r} (expected {SCHEMA_VERSION!r})"
            raise ValueError(msg)
        return v

    _v_message_id = field_validator("message_id")(_validate_ulid)
    _v_idempotency_key = field_validator("idempotency_key")(_validate_ulid)
    _v_sender_id = field_validator("sender_id")(_validate_ulid)
    _v_recipient_id = field_validator("recipient_id")(_validate_ulid)
    _v_issued_at = field_validator("issued_at")(_validate_rfc3339)


def envelope_signing_payload(envelope: WireEnvelope) -> bytes:
    """Canonical bytes of the envelope, excluding `signature` (invariant 13)."""
    data = envelope.model_dump(mode="json")
    data.pop("signature", None)
    return canonical_bytes(data)


def envelope_fingerprint(envelope: WireEnvelope) -> str:
    """SHA-256 of the FULL canonical envelope (signature included).

    The idempotency store keeps this per key: the same key re-arriving with a
    different fingerprint is hostile, not a retry (ADR-0007, wire level).
    """
    return hashlib.sha256(canonical_bytes(envelope.model_dump(mode="json"))).hexdigest()


@dataclass(frozen=True)
class GatewayIdentity:
    """A gateway's wire identity (ADR-0012): ULID + Ed25519 identity key.

    Distinct from the ledger event-chain signing key. `private_key` is None
    for verify-only peers (we hold their public key, not their seed).
    Never logged or persisted to the repo (invariant 12).
    """

    identity_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey | None = None

    @classmethod
    def from_seed(cls, identity_id: str, seed: bytes) -> GatewayIdentity:
        private_key = load_private_key(seed)
        return cls(
            identity_id=identity_id, public_key=private_key.public_key(), private_key=private_key
        )

    @property
    def public_key_b64url(self) -> str:
        return b64url_encode(public_key_raw(self.public_key))


def load_peer_identity(identity_id: str, public_key_b64url: str) -> GatewayIdentity:
    """Register a peer from its public key (pre-shared, ADR-0012)."""
    try:
        raw = b64url_decode(public_key_b64url)
    except ValueError as exc:
        raise EnvelopeError(f"peer public key is not valid base64url: {exc}") from exc
    try:
        public_key = load_public_key(raw)
    except ValueError as exc:
        raise EnvelopeError(f"peer public key is not a 32-byte Ed25519 key: {exc}") from exc
    return GatewayIdentity(identity_id=identity_id, public_key=public_key)


def make_envelope(
    *,
    kind: MessageKind,
    payload: BaseModel,
    sender: GatewayIdentity,
    recipient_id: str,
    message_id: str,
    idempotency_key: str,
    issued_at: str,
) -> WireEnvelope:
    """Mint + sign an envelope with `sender`'s identity key.

    Caller supplies ids and time (no clock in this layer, invariant 2).
    """
    if sender.private_key is None:
        msg = "cannot sign with a verify-only identity"
        raise EnvelopeError(msg)
    provisional = WireEnvelope(
        schema_version=SCHEMA_VERSION,
        message_id=message_id,
        idempotency_key=idempotency_key,
        sender_id=sender.identity_id,
        recipient_id=recipient_id,
        kind=kind,
        payload=payload.model_dump(mode="json"),
        issued_at=issued_at,
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=sender.identity_id, value=""),
    )
    value = sign(sender.private_key, envelope_signing_payload(provisional))
    data = provisional.model_dump(mode="json")
    data["signature"] = {"algorithm": ALGORITHM, "key_id": sender.identity_id, "value": value}
    return WireEnvelope.model_validate(data)


def verify_envelope(envelope: WireEnvelope, peer: GatewayIdentity) -> None:
    """Verify-first checks for one inbound envelope (ADR-0012 pipeline).

    Raises EnvelopeError with the reason on the first failed check. The
    caller is responsible for matching `envelope.sender_id` to the right
    registered peer before calling this.
    """
    if envelope.schema_version != SCHEMA_VERSION:
        msg = f"unsupported schema_version {envelope.schema_version!r}"
        raise EnvelopeError(msg)
    if envelope.sender_id != peer.identity_id:
        msg = (
            f"envelope sender_id {envelope.sender_id} does not match registered peer "
            f"{peer.identity_id}"
        )
        raise EnvelopeError(msg)
    if envelope.signature.algorithm != ALGORITHM:
        msg = f"algorithm spoof: expected {ALGORITHM!r}, got {envelope.signature.algorithm!r}"
        raise EnvelopeError(msg)
    if envelope.signature.key_id != peer.identity_id:
        msg = f"key_id {envelope.signature.key_id!r} is not this peer's identity key"
        raise EnvelopeError(msg)
    try:
        raw = b64url_decode(envelope.signature.value)
    except ValueError as exc:
        raise EnvelopeError(f"signature is not valid base64url: {exc}") from exc
    try:
        peer.public_key.verify(raw, envelope_signing_payload(envelope))
    except Exception as exc:
        raise EnvelopeError("signature does not verify against the peer's registered key") from exc


def envelope_is_stale(envelope: WireEnvelope, now: str, max_age_seconds: int) -> bool:
    """First-seen freshness check (audit A2 #8 / Part C #5).

    True when `envelope.issued_at` is more than `max_age_seconds` away from
    the receiver's clock `now` — in either direction, so a small clock skew
    does not reject honest peers. `now` is supplied by the boundary
    (invariant 2: no clock in this layer). A signature-valid envelope this
    old is either a slow original or a replay; both are rejected, and the
    sender may retry with a new idempotency key.
    """
    try:
        issued = datetime.fromisoformat(envelope.issued_at)
        received = datetime.fromisoformat(now)
    except ValueError:
        return True
    if issued.tzinfo is None or received.tzinfo is None:
        return True
    return abs((received - issued).total_seconds()) > max_age_seconds


def parse_payload(envelope: WireEnvelope) -> BaseModel:
    """Validate the payload dict against its kind's model (verify-first stage 1)."""
    model = _PAYLOAD_MODELS[envelope.kind]
    try:
        return model.model_validate(envelope.payload)
    except Exception as exc:
        raise EnvelopeError(f"payload is not a valid {envelope.kind.value} payload: {exc}") from exc


def verify_receipt(
    receipt: WireEnvelope,
    peer: GatewayIdentity,
    *,
    expected_responds_to: str,
    now: str | None = None,
    max_age_seconds: int | None = None,
) -> ReceiptPayload:
    """Counterparty-side verification of a receipt we received (Phase 6).

    A receipt is the peer gateway's signed answer to one of our messages.
    Trusting it without verifying would let a forged, tampered, or replayed
    receipt fake an allow/deny back to the agent (threat-walkthrough Phase-6
    row), so the counterparty runs this on every receipt before reading its
    outcome: the signature must verify against the registered peer identity,
    the kind must be `receipt`, and `responds_to` must be our own
    `message_id` — a genuine receipt for a *different* message is a replay,
    not an answer (the binding `verify_envelope` alone does not check).
    Freshness applies when `max_age_seconds` is supplied; with it, `now`
    must be supplied too — the check is fail-closed, never skipped.
    `now` is boundary-supplied (invariant 2).
    """
    if receipt.kind is not MessageKind.RECEIPT:
        msg = f"envelope kind {receipt.kind.value!r} is not a receipt"
        raise EnvelopeError(msg)
    verify_envelope(receipt, peer)
    payload = parse_payload(receipt)
    if not isinstance(payload, ReceiptPayload):
        msg = f"payload did not parse as a receipt payload (kind {receipt.kind.value!r})"
        raise EnvelopeError(msg)
    if payload.responds_to != expected_responds_to:
        msg = (
            f"receipt responds to {payload.responds_to}, not our message "
            f"{expected_responds_to}; it is not an answer to this message"
        )
        raise EnvelopeError(msg)
    if max_age_seconds is not None:
        if now is None:
            msg = "max_age_seconds was supplied without now; the freshness check cannot be skipped"
            raise EnvelopeError(msg)
        if envelope_is_stale(receipt, now, max_age_seconds):
            msg = f"receipt is stale: issued_at is outside the {max_age_seconds}s freshness window"
            raise EnvelopeError(msg)
    return payload
