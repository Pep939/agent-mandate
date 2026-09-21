"""Shared, structurally valid factories for Phase 1 tests.

`make_input()` with no arguments is the *allow* baseline: an agent proposes
`request_quote` on a DRAFT deal under a mandate that allows every action,
carries a generous USD spend cap, and is active at `NOW`.
"""

from __future__ import annotations

import base64
import itertools
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from mandate.crypto.signing import GatewaySigner, generate_keypair
from mandate.domain.authority import (
    ActionToken,
    AuthorityClaim,
    AuthorityRecord,
    RecordStatus,
    SignatureBlock,
    SpendCap,
)
from mandate.domain.content import ContentClaims, DetectedField
from mandate.domain.deals import Deal, DealState
from mandate.domain.input import Actor, ActorKind, Counterparty, PolicyInput, Proposal

CONTENT_SHA = "a" * 64
QUESTION_SET_SHA = "b" * 64


def make_claims(
    detected: dict[str, int] | None = None,
    *,
    hostility_bp: int = 0,
    persuasion_bp: int = 0,
    urgency_level: int = 0,
    available: bool = True,
    screener: str = "fixture:test-0.1",
) -> ContentClaims:
    """ADR-0016 content claims. `detected` maps field token → basis points."""
    return ContentClaims(
        screener=screener,
        question_set_sha256=QUESTION_SET_SHA,
        content_chars=42,
        available=available,
        detected=[
            DetectedField(field=f, confidence_bp=bp) for f, bp in sorted((detected or {}).items())
        ],
        hostility_bp=hostility_bp,
        persuasion_bp=persuasion_bp,
        urgency_level=urgency_level,
    )


NOW = "2026-01-15T12:00:00Z"
PAST = "2026-01-01T00:00:00Z"
FUTURE = "2027-01-01T00:00:00Z"

_counter = itertools.count(1)


def new_ulid() -> str:
    """Deterministic, unique-per-process, valid 26-char Crockford base32 ULID.

    Zero-padded to the full 26 characters rather than to a 4-digit tail: a
    Hypothesis run makes tens of thousands of these, and a narrower counter
    silently overflows the length and fails validation mid-suite.
    """
    return f"{next(_counter):026d}"


def _signature() -> SignatureBlock:
    return SignatureBlock(algorithm="ed25519", key_id="test-key", value="test-signature")


def make_signer() -> GatewaySigner:
    """A fresh ephemeral gateway key (invariant 12: never persisted)."""
    private_key, public_key = generate_keypair()
    return GatewaySigner(key_id="test-gateway-key", private_key=private_key, public_key=public_key)


def write_key_file(tmp_path: Path, key_id: str, private_key) -> Path:
    """A key file in the `scripts/dev_keys.py` JSON shape (C1 custody)."""
    payload = {
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": _b64url_raw(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        "private_seed": _b64url_raw(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ),
    }
    path = tmp_path / f"{key_id}.ed25519.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _b64url_raw(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_record(**overrides: Any) -> AuthorityRecord:
    defaults: dict[str, Any] = {
        "schema_version": "0.1",
        "record_id": new_ulid(),
        "principal_id": new_ulid(),
        "agent_id": new_ulid(),
        "counterparty_id": None,
        "purpose": "unit test mandate",
        "allowed_actions": list(ActionToken),
        "prohibited_actions": [],
        "spend_cap": SpendCap(currency="USD", amount_minor=1_000_000),
        "max_negotiation_rounds": 10,
        "acceptance_window_hours": 48,
        "silent_acceptance": False,
        "disclosure_fields": [],
        "requires_human_approval_for": [],
        "issued_at": PAST,
        "not_before": PAST,
        "expires_at": FUTURE,
        "parent_record_id": None,
        "status": RecordStatus.ACTIVE,
        "nonce": new_ulid(),
        "signature": _signature(),
    }
    defaults.update(overrides)
    return AuthorityRecord(**defaults)


def make_claim(record: AuthorityRecord | None = None, **overrides: Any) -> AuthorityClaim:
    rec = record if record is not None else make_record()
    defaults: dict[str, Any] = {
        "record": rec,
        "signature_valid": True,
        "delegation_chain": [],
        "status": rec.status,
    }
    defaults.update(overrides)
    return AuthorityClaim(**defaults)


def make_deal(state: DealState = DealState.DRAFT, **overrides: Any) -> Deal:
    defaults: dict[str, Any] = {
        "deal_id": new_ulid(),
        "state": state,
        "negotiated_rounds": 0,
        "committed_minor": 0,
        "open_disputes": 0,
        "open_approvals": 0,
    }
    defaults.update(overrides)
    return Deal(**defaults)


def make_proposal(
    action: str = "request_quote", deal_id: str | None = None, **overrides: Any
) -> Proposal:
    defaults: dict[str, Any] = {
        "action": action,
        "deal_id": deal_id if deal_id is not None else new_ulid(),
        "amount_minor": None,
        "currency": "USD",
        "disclosure_fields": [],
        "idempotency_key": new_ulid(),
    }
    defaults.update(overrides)
    return Proposal(**defaults)


def make_input(
    record: AuthorityRecord | None = None,
    claim: AuthorityClaim | None = None,
    deal: Deal | None = None,
    proposal: Proposal | None = None,
    actor: Actor | None = None,
    counterparty: Counterparty | None = None,
    schema_version: str = "0.1",
    now: str = NOW,
    request_id: str | None = None,
    content: ContentClaims | None = None,
) -> PolicyInput:
    rec = record if record is not None else make_record()
    clm = claim if claim is not None else make_claim(rec)
    d = deal if deal is not None else make_deal()
    prop = proposal if proposal is not None else make_proposal(deal_id=d.deal_id)
    if content is not None and prop.content_sha256 is None:
        prop = prop.model_copy(update={"content_sha256": CONTENT_SHA})
    return PolicyInput(
        schema_version=schema_version,
        request_id=request_id if request_id is not None else new_ulid(),
        now=now,
        actor=actor if actor is not None else Actor(kind=ActorKind.AGENT, id=rec.agent_id),
        authority=clm,
        counterparty=counterparty if counterparty is not None else Counterparty(id=None),
        deal=d,
        proposal=prop,
        content=content,
    )
