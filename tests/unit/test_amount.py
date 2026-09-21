"""Money construction rule: `amount_minor` is non-negative integer minor units.

A negative amount is rejected at the domain boundary (model construction), not
clamped in any single presentation layer, so it can never reach cumulative
spend from any entry path — the console form, the policy engine, or a signed
wire envelope (the wire path the form parser never sees; invariant 8). `None`
and `0` are valid; the float guard from ADR-0005 is preserved.
"""

from __future__ import annotations

import pytest

from mandate.domain.approvals import Approval, ApprovalRecord, ApprovalStatus
from mandate.domain.authority import SignatureBlock, SpendCap
from mandate.domain.decisions import ReasonCode
from mandate.domain.input import Proposal
from mandate.transport.envelope import ProposalPayload
from tests.support.factories import new_ulid

TS = "2026-01-15T12:00:00Z"


def _proposal(amount_minor: int | None) -> Proposal:
    return Proposal(
        action="accept_agreement",
        deal_id=new_ulid(),
        amount_minor=amount_minor,
        currency="USD",
        disclosure_fields=[],
        idempotency_key=new_ulid(),
    )


def _proposal_payload(amount_minor: int | None) -> ProposalPayload:
    return ProposalPayload(
        action="accept_agreement",
        deal_id=new_ulid(),
        amount_minor=amount_minor,
        currency="USD",
        disclosure_fields=[],
        idempotency_key=new_ulid(),
    )


def _approval_record(amount_minor: int | None) -> ApprovalRecord:
    return ApprovalRecord(
        schema_version="0.1",
        approval_record_id=new_ulid(),
        deal_id=new_ulid(),
        request_id=new_ulid(),
        parent_authority_record_id=new_ulid(),
        action="capture_payment",
        amount_minor=amount_minor,
        currency="USD",
        proposal_digest="deadbeef",
        issued_at=TS,
        signature=SignatureBlock(algorithm="ed25519", key_id="k", value="sig"),
    )


def _approval(amount_minor: int | None) -> Approval:
    return Approval(
        approval_id=new_ulid(),
        deal_id=new_ulid(),
        request_id=new_ulid(),
        authority_record_id=new_ulid(),
        action="capture_payment",
        amount_minor=amount_minor,
        currency="USD",
        proposal_digest="deadbeef",
        reason_code=ReasonCode.APPROVAL_REQUIRED,
        status=ApprovalStatus.PENDING,
        decided_by=None,
        decided_at=None,
        command_id=None,
        created_at=TS,
    )


@pytest.mark.parametrize(
    "build",
    [_proposal, _proposal_payload, _approval_record, _approval],
    ids=["proposal", "wire_payload", "approval_record", "approval"],
)
def test_negative_amount_is_rejected_at_construction(build) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        build(-1)


def test_spend_cap_rejects_negative() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        SpendCap(currency="USD", amount_minor=-1)


@pytest.mark.parametrize("build", [_proposal, _proposal_payload, _approval_record, _approval])
def test_zero_amount_is_allowed(build) -> None:
    assert build(0).amount_minor == 0


def test_zero_spend_cap_is_allowed() -> None:
    assert SpendCap(currency="USD", amount_minor=0).amount_minor == 0


def test_none_amount_is_allowed() -> None:
    assert _proposal(None).amount_minor is None
    assert _proposal_payload(None).amount_minor is None


@pytest.mark.parametrize("build", [_proposal, _proposal_payload])
def test_non_integer_float_is_still_rejected(build) -> None:
    with pytest.raises(ValueError, match="float"):
        build(1.5)
