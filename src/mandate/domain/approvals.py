"""Approval lifecycle models (ADR-0010, ADR-0004 A2/P2).

Two distinct objects:

- ``Approval`` — the boundary's tracking row for one approval
  (pending → granted | denied). Mutable lifecycle state; **not** a ledger
  event.
- ``ApprovalRecord`` — the signed, single-use one-time override minted on
  grant. Bound to the specific proposal (``proposal_digest`` + action +
  amount) and independently verifiable (invariant 13/15).

Pure models: no I/O, no clock (``created_at``/``issued_at``/``decided_at`` are
supplied by the boundary, invariant 2).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from mandate.domain.authority import (
    SignatureBlock,
    _validate_rfc3339,
    _validate_ulid,
    validate_amount_minor,
)
from mandate.domain.decisions import ReasonCode

__all__ = ["Approval", "ApprovalRecord", "ApprovalStatus"]


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"


class ApprovalRecord(BaseModel):
    """A signed, single-use grant by the approving principal, bound to one
    proposal (ADR-0004 A2/P2). Verify with ``verify_approval``."""

    model_config = ConfigDict(frozen=True)

    schema_version: str
    approval_record_id: str
    deal_id: str
    request_id: str
    parent_authority_record_id: str
    action: str
    amount_minor: int | None
    currency: str
    proposal_digest: str
    issued_at: str
    signature: SignatureBlock

    _v_record_id = field_validator("approval_record_id")(_validate_ulid)
    _v_deal_id = field_validator("deal_id")(_validate_ulid)
    _v_request_id = field_validator("request_id")(_validate_ulid)
    _v_parent = field_validator("parent_authority_record_id")(_validate_ulid)
    _v_issued_at = field_validator("issued_at")(_validate_rfc3339)
    _v_amount_minor = field_validator("amount_minor")(validate_amount_minor)


class Approval(BaseModel):
    """Boundary tracking row for one approval (ADR-0010). ``decided_*`` and
    ``command_id`` are set once the approval moves out of pending."""

    model_config = ConfigDict(frozen=True)

    approval_id: str
    deal_id: str
    request_id: str
    authority_record_id: str
    action: str
    amount_minor: int | None
    currency: str
    proposal_digest: str
    reason_code: ReasonCode
    status: ApprovalStatus
    decided_by: str | None
    decided_at: str | None
    command_id: str | None
    created_at: str

    _v_approval_id = field_validator("approval_id")(_validate_ulid)
    _v_deal_id = field_validator("deal_id")(_validate_ulid)
    _v_request_id = field_validator("request_id")(_validate_ulid)
    _v_record_id = field_validator("authority_record_id")(_validate_ulid)
    _v_created_at = field_validator("created_at")(_validate_rfc3339)
    _v_amount_minor = field_validator("amount_minor")(validate_amount_minor)

    @field_validator("decided_at")
    @classmethod
    def _v_decided_at(cls, v: str | None) -> str | None:
        if v is not None:
            return _validate_rfc3339(v)
        return v

    @field_validator("command_id")
    @classmethod
    def _v_command_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v
