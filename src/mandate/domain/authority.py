"""Authority record models — the signed, scoped, revocable mandate.

An authority record describes *permission*; it does not prove an action
occurred. Proof of occurrence is the event ledger (Phase 3+).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

ULID_RE = re.compile(r"^[0-9A-HJKMNPQRSTVWXYZ]{26}$", re.IGNORECASE)

_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def _validate_ulid(v: str) -> str:
    if not ULID_RE.match(v):
        msg = f"not a valid ULID (26-char Crockford base32): {v!r}"
        raise ValueError(msg)
    return v


def _validate_rfc3339(v: str) -> str:
    """Validate an RFC3339 timestamp and normalize it to UTC `Z` form.

    Normalization at construction makes canonical bytes stable regardless of
    the offset the caller used (envelope spec, ADR-0005).
    """
    if not _RFC3339_RE.match(v):
        msg = f"not a valid RFC3339 timestamp: {v!r}"
        raise ValueError(msg)
    dt = datetime.fromisoformat(v.replace("z", "Z").replace("Z", "+00:00"))
    if dt.tzinfo is None:
        msg = f"timestamp must carry a UTC offset: {v!r}"
        raise ValueError(msg)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def validate_amount_minor(v: int | None) -> int | None:
    """Money is non-negative integer minor units; `None` means no amount."""
    if isinstance(v, float):
        msg = "amount_minor must be an integer, not float"
        raise ValueError(msg)
    if v is not None and v < 0:
        msg = f"amount_minor must be non-negative: {v}"
        raise ValueError(msg)
    return v


class ActionToken(StrEnum):
    """Closed 13-token action vocabulary (ADR-0004 P1)."""

    REQUEST_QUOTE = "request_quote"
    COUNTEROFFER = "counteroffer"
    ACCEPT_AGREEMENT = "accept_agreement"
    START_WORK = "start_work"
    PROPOSE_CHANGE = "propose_change"
    APPROVE_CHANGE_ORDER = "approve_change_order"
    CLAIM_COMPLETION = "claim_completion"
    ACCEPT_COMPLETION = "accept_completion"
    OPEN_DISPUTE = "open_dispute"
    INITIATE_PAYMENT = "initiate_payment"
    CAPTURE_PAYMENT = "capture_payment"
    CANCEL_DEAL = "cancel_deal"
    RESOLVE_DISPUTE = "resolve_dispute"


class RecordStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SpendCap(BaseModel):
    model_config = ConfigDict(frozen=True)

    currency: str
    amount_minor: int

    _v_amount = field_validator("amount_minor")(validate_amount_minor)

    @field_validator("currency")
    @classmethod
    def _iso4217(cls, v: str) -> str:
        if len(v) != 3 or not v.isalpha():
            msg = f"currency must be ISO-4217 (3 letters): {v!r}"
            raise ValueError(msg)
        return v.upper()


class SignatureBlock(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str
    key_id: str
    value: str


class AuthorityRecord(BaseModel):
    """The signed, scoped, revocable mandate (brief §10)."""

    model_config = ConfigDict(frozen=True)

    schema_version: str
    record_id: str
    principal_id: str
    agent_id: str
    counterparty_id: str | None
    purpose: str
    allowed_actions: list[ActionToken]
    prohibited_actions: list[ActionToken]
    spend_cap: SpendCap
    max_negotiation_rounds: int
    acceptance_window_hours: int
    silent_acceptance: bool = False
    disclosure_fields: list[str]
    requires_human_approval_for: list[ActionToken]
    issued_at: str
    not_before: str
    expires_at: str
    parent_record_id: str | None
    status: RecordStatus
    nonce: str
    signature: SignatureBlock

    _v_record_id = field_validator("record_id")(_validate_ulid)
    _v_principal_id = field_validator("principal_id")(_validate_ulid)
    _v_agent_id = field_validator("agent_id")(_validate_ulid)
    _v_issued_at = field_validator("issued_at")(_validate_rfc3339)
    _v_not_before = field_validator("not_before")(_validate_rfc3339)
    _v_expires_at = field_validator("expires_at")(_validate_rfc3339)

    @field_validator("counterparty_id")
    @classmethod
    def _v_counterparty(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v

    @field_validator("parent_record_id")
    @classmethod
    def _v_parent(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v


class Revocation(BaseModel):
    """A signed fact revoking one authority record (envelope spec:
    `active --(revoke, signed)--> revoked`). Terminal and immediate
    (invariant 7); revoking a parent revokes all descendants (ADR-0006)."""

    model_config = ConfigDict(frozen=True)

    schema_version: str
    revocation_id: str
    record_id: str
    revoked_at: str
    signature: SignatureBlock

    _v_revocation_id = field_validator("revocation_id")(_validate_ulid)
    _v_record_id = field_validator("record_id")(_validate_ulid)
    _v_revoked_at = field_validator("revoked_at")(_validate_rfc3339)


class DelegationLink(BaseModel):
    model_config = ConfigDict(frozen=True)

    parent_record_id: str
    scope_narrowing_valid: bool

    _v_parent = field_validator("parent_record_id")(_validate_ulid)


class AuthorityClaim(BaseModel):
    """Boundary-supplied claim wrapping the record with verified metadata."""

    model_config = ConfigDict(frozen=True)

    record: AuthorityRecord
    signature_valid: bool
    delegation_chain: list[DelegationLink]
    status: RecordStatus
