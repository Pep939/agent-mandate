"""Pure event-chain helpers (ADR-0008: no DB driver, no I/O in this package).

`build_event` assigns the two hashes and the gateway signature; `verify_chain`
is the tamper detector: it recomputes every hash, checks sequence and linkage
and verifies every signature (brief §13, suites B/C).
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mandate.crypto.canonicalization import canonical_bytes, canonical_sha256_hex
from mandate.crypto.signing import ALGORITHM, GatewaySigner, b64url_decode
from mandate.domain.authority import ActionToken
from mandate.domain.deals import Deal, DealEvent
from mandate.domain.decisions import Outcome
from mandate.domain.events import (
    GENESIS_HASH,
    Event,
    EventSignature,
    EventType,
    event_signing_bytes,
)
from mandate.domain.input import ActorKind
from mandate.domain.state_machine import ACTION_EVENTS, transition_for

__all__ = [
    "ChainCheck",
    "ChainReport",
    "build_event",
    "make_event_id",
    "plan_transition",
    "verify_chain",
]

_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ms_from_rfc3339(value: str) -> int:
    """Whole milliseconds since epoch of an explicit timestamp (no clock)."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        msg = f"timestamp must carry a UTC offset: {value!r}"
        raise ValueError(msg)
    return int(dt.astimezone(UTC).timestamp() * 1000)


def _crockford32(value: int, length: int) -> str:
    chars: list[str] = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def make_event_id(recorded_at: str) -> str:
    """128-bit ULID: 48-bit ms from the boundary-supplied timestamp + 80
    random bits. Sortable by creation time; unique per call."""
    bits = (_ms_from_rfc3339(recorded_at) << 80) | int.from_bytes(secrets.token_bytes(10), "big")
    return _crockford32(bits, 26)


def build_event(
    *,
    event_id: str,
    deal_id: str,
    sequence_number: int,
    event_type: EventType,
    actor_kind: ActorKind,
    actor_id: str,
    authority_record_id: str | None,
    previous_event_hash: str,
    payload: dict[str, object],
    occurred_at: str,
    recorded_at: str,
    signer: GatewaySigner,
) -> Event:
    """Construct a consistent, signed Event (hashes validated in the model)."""
    payload_hash = canonical_sha256_hex(payload)
    form: dict[str, object] = {
        "event_id": event_id,
        "deal_id": deal_id,
        "sequence_number": sequence_number,
        "event_type": event_type.value,
        "actor_kind": actor_kind.value,
        "actor_id": actor_id,
        "authority_record_id": authority_record_id,
        "previous_event_hash": previous_event_hash,
        "payload_hash": payload_hash,
        "payload": payload,
        "occurred_at": occurred_at,
        "recorded_at": recorded_at,
    }
    signing_payload = canonical_bytes(form)
    event_hash = hashlib.sha256(signing_payload).hexdigest()
    return Event(
        event_id=event_id,
        deal_id=deal_id,
        sequence_number=sequence_number,
        event_type=event_type,
        actor_kind=actor_kind,
        actor_id=actor_id,
        authority_record_id=authority_record_id,
        previous_event_hash=previous_event_hash,
        payload_hash=payload_hash,
        event_hash=event_hash,
        payload=payload,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        signature=EventSignature(
            algorithm=ALGORITHM, key_id=signer.key_id, value=signer.sign_bytes(signing_payload)
        ),
    )


def plan_transition(
    deal: Deal, action: str, outcome: Outcome
) -> tuple[DealEvent | None, str | None]:
    """Recheck an ALLOWed action against the *stored* deal (invariant 3).

    Returns (event, None) to proceed — event None means decision-only
    (resolve_dispute) or a non-ALLOW outcome — or (None, abort_detail).
    """
    if outcome is not Outcome.ALLOW:
        return None, None
    try:
        token = ActionToken(action)
    except ValueError:
        return None, "stale_state: action not in the closed vocabulary"
    event = ACTION_EVENTS[token]
    if event is None:
        return None, None
    if transition_for(deal.state, event) is None:
        return None, (
            f"stale_state: action {action!r} is not valid from stored state {deal.state.value}"
        )
    return event, None


@dataclass(frozen=True)
class ChainCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class ChainReport:
    deal_id: str
    ok: bool
    checks: tuple[ChainCheck, ...]

    def first_failure(self) -> ChainCheck | None:
        for check in self.checks:
            if not check.ok:
                return check
        return None


def _verify_sig(
    public_key: Ed25519PublicKey, payload: bytes, signature: EventSignature
) -> tuple[bool, str]:
    if signature.algorithm != ALGORITHM:
        return False, f"unexpected algorithm {signature.algorithm!r}"
    try:
        raw = b64url_decode(signature.value)
        public_key.verify(raw, payload)
    except (InvalidSignature, ValueError) as exc:
        return False, f"invalid signature: {type(exc).__name__}"
    return True, "ok"


def verify_chain(events: Sequence[Event], public_key: Ed25519PublicKey) -> ChainReport:
    """Recompute and check the whole chain (brief §13 verification utility).

    Detects edits (payload/event hash), forgeries (signature) and reordering
    (sequence + linkage). A truncated re-export of a prefix still
    self-verifies here; that case is caught by the signed evidence-bundle
    summary — see specs/evidence-bundle.md (ADR-0015).
    """
    checks: list[ChainCheck] = []
    previous = GENESIS_HASH
    for index, event in enumerate(events):
        try:
            payload_ok = event.payload_hash == canonical_sha256_hex(event.payload)
            payload_detail = "ok" if payload_ok else "payload_hash does not match payload"
        except (ValueError, TypeError) as exc:
            payload_ok, payload_detail = False, f"payload not canonical: {exc}"
        checks.append(ChainCheck(f"event_{index}_payload_hash", payload_ok, payload_detail))

        form_bytes = event_signing_bytes(event)
        hash_ok = event.event_hash == hashlib.sha256(form_bytes).hexdigest()
        checks.append(
            ChainCheck(
                f"event_{index}_event_hash",
                hash_ok,
                "ok" if hash_ok else "event_hash does not match the canonical event form",
            )
        )

        sig_ok, sig_detail = _verify_sig(public_key, form_bytes, event.signature)
        checks.append(ChainCheck(f"event_{index}_signature", sig_ok, sig_detail))

        seq_ok = event.sequence_number == index
        checks.append(
            ChainCheck(
                f"event_{index}_sequence",
                seq_ok,
                "ok" if seq_ok else f"sequence {event.sequence_number}, expected {index}",
            )
        )

        link_ok = event.previous_event_hash == previous
        checks.append(
            ChainCheck(
                f"event_{index}_chain_link",
                link_ok,
                "ok"
                if link_ok
                else "previous_event_hash does not equal the prior event's event_hash",
            )
        )

        if payload_ok and hash_ok and sig_ok and seq_ok and link_ok:
            previous = event.event_hash

    report_checks = tuple(checks)
    deal_id = events[0].deal_id if events else ""
    return ChainReport(deal_id=deal_id, ok=all(c.ok for c in report_checks), checks=report_checks)
