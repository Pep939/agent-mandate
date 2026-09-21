"""Boundary assembly for the console (ADR-0011).

Turns a stored record into the immutable `AuthorityClaim` the engine consumes:
verify the signature against the gateway public key, check applicable
revocations, and resolve the lifecycle status. This is the only place that
touches crypto verification / the domain lifecycle, and the only place a clock
enters (invariant 2: time is supplied here, not in the domain).
"""

from __future__ import annotations

import random
import time
from datetime import UTC, datetime

from mandate.api.state import AppState
from mandate.application.claims import build_claim as claims_build_claim
from mandate.crypto.canonicalization import record_signing_payload, revocation_signing_payload
from mandate.crypto.signing import ALGORITHM
from mandate.domain.authority import (
    ActionToken,
    AuthorityClaim,
    AuthorityRecord,
    Revocation,
    SignatureBlock,
    SpendCap,
)
from mandate.domain.deals import Deal, DealState

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

__all__ = [
    "build_claim",
    "make_default_record",
    "make_signed_record",
    "make_signed_revocation",
    "new_ulid",
    "now_iso",
    "register_deal",
    "seed_demo",
]


def new_ulid() -> str:
    rng = random.SystemRandom()
    ts = int(time.time() * 1000)
    out = []
    for _ in range(10):
        out.append(CROCKFORD[ts % 32])
        ts //= 32
    for _ in range(16):
        out.append(CROCKFORD[rng.getrandbits(5)])
    return "".join(out)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def make_signed_record(
    state: AppState,
    *,
    now: str,
    agent_id: str,
    principal_id: str,
    purpose: str,
    allowed_actions: list[str],
    spend_cap_currency: str,
    spend_cap_minor: int,
    max_negotiation_rounds: int,
    expires_at: str,
    prohibited_actions: list[str] | None = None,
    disclosure_fields: list[str] | None = None,
    requires_human_approval_for: list[str] | None = None,
    counterparty_id: str | None = None,
    acceptance_window_hours: int = 48,
    silent_acceptance: bool = False,
) -> AuthorityRecord:
    """Build + sign an active top-level mandate with the gateway key.

    The signature covers the canonical bytes excluding the signature
    (invariant 13); `issued_at`/`not_before` come from the boundary clock.
    """
    unsigned = AuthorityRecord(
        schema_version="0.1",
        record_id=new_ulid(),
        principal_id=principal_id,
        agent_id=agent_id,
        counterparty_id=counterparty_id,
        purpose=purpose,
        allowed_actions=list(allowed_actions),
        prohibited_actions=list(prohibited_actions or ()),
        spend_cap=SpendCap(currency=spend_cap_currency, amount_minor=spend_cap_minor),
        max_negotiation_rounds=max_negotiation_rounds,
        acceptance_window_hours=acceptance_window_hours,
        silent_acceptance=silent_acceptance,
        disclosure_fields=list(disclosure_fields or ()),
        requires_human_approval_for=list(requires_human_approval_for or ()),
        issued_at=now,
        not_before=now,
        expires_at=expires_at,
        parent_record_id=None,
        status="active",
        nonce=new_ulid(),
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=state.signer.key_id, value=""),
    )
    value = state.signer.sign_bytes(record_signing_payload(unsigned))
    return unsigned.model_copy(
        update={
            "signature": SignatureBlock(
                algorithm=ALGORITHM, key_id=state.signer.key_id, value=value
            )
        }
    )


def make_signed_revocation(state: AppState, *, record_id: str, now: str) -> Revocation:
    unsigned = Revocation(
        schema_version="0.1",
        revocation_id=new_ulid(),
        record_id=record_id,
        revoked_at=now,
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=state.signer.key_id, value=""),
    )
    value = state.signer.sign_bytes(revocation_signing_payload(unsigned))
    return unsigned.model_copy(
        update={
            "signature": SignatureBlock(
                algorithm=ALGORITHM, key_id=state.signer.key_id, value=value
            )
        }
    )


def build_claim(state: AppState, record: AuthorityRecord, *, now: str) -> AuthorityClaim:
    """Verify the record and resolve its status at `now` (invariant 3/7).

    Delegates to `application.claims.build_claim` — the wire gateway
    (ADR-0012) shares the same crypto→claim assembly (invariant 3, at
    decision time).
    """
    return claims_build_claim(state.store, state.signer, record, now=now)


def make_default_record(state: AppState, now: str, purpose: str) -> AuthorityRecord:
    """A permissive demo mandate: all actions allowed, $10,000 cap, and
    `capture_payment` needs a person's sign-off (so the approval flow is
    exercisable)."""
    return make_signed_record(
        state,
        now=now,
        agent_id=new_ulid(),
        principal_id=new_ulid(),
        purpose=purpose,
        allowed_actions=[a.value for a in ActionToken],
        spend_cap_currency="USD",
        spend_cap_minor=1_000_000,
        max_negotiation_rounds=10,
        expires_at="2027-01-01T00:00:00+00:00",
        requires_human_approval_for=["capture_payment"],
    )


def register_deal(state: AppState, deal_id: str, record: AuthorityRecord, created_at: str) -> None:
    deal = Deal(
        deal_id=deal_id,
        state=DealState.DRAFT,
        negotiated_rounds=0,
        committed_minor=0,
        open_disputes=0,
        open_approvals=0,
    )
    state.store.create_deal(deal, created_at)
    state.store.put_record(record)
    state.store.link_deal_record(deal_id, record.record_id, created_at)
    state.deal_ids.append(deal_id)
    state.deal_records[deal_id] = record.record_id


def seed_demo(state: AppState) -> str:
    """Create one demo deal + a signed active mandate so the console has a
    working starting point. Returns the deal_id."""
    now = now_iso()
    deal_id = new_ulid()
    record = make_default_record(state, now, "Demo mandate: full lifecycle")
    register_deal(state, deal_id, record, now)
    return deal_id
