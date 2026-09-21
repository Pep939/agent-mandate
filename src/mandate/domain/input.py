"""PolicyInput — the sole input to the pure evaluation function.

All verified claims (signature, delegation, status) and the trusted clock
(`now`) are supplied by the application boundary as immutable fields.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from mandate.domain.authority import (
    AuthorityClaim,
    _validate_rfc3339,
    _validate_ulid,
    validate_amount_minor,
)
from mandate.domain.content import ContentClaims, validate_sha256_hex
from mandate.domain.deals import Deal


class ActorKind(StrEnum):
    PRINCIPAL = "principal"
    AGENT = "agent"
    SYSTEM = "system"
    COUNTERPARTY = "counterparty"


class Actor(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: ActorKind
    id: str

    _v_id = field_validator("id")(_validate_ulid)


class Counterparty(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str | None

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str | None) -> str | None:
        if v is not None:
            _validate_ulid(v)
        return v


class Proposal(BaseModel):
    """Untrusted agent proposal. `action` is str, not ActionToken, to model
    raw agent input that the engine validates."""

    model_config = ConfigDict(frozen=True)

    action: str
    deal_id: str
    amount_minor: int | None = None
    currency: str
    disclosure_fields: list[str] = []
    idempotency_key: str
    content_sha256: str | None = None
    """SHA-256 of the exact content bytes the action would send (ADR-0016).
    The text itself never enters the domain; the digest binds the proposal
    (and so the anti-replay digest) to what was screened."""

    _v_deal_id = field_validator("deal_id")(_validate_ulid)
    _v_idempotency_key = field_validator("idempotency_key")(_validate_ulid)
    _v_amount_minor = field_validator("amount_minor")(validate_amount_minor)

    @field_validator("content_sha256")
    @classmethod
    def _v_content(cls, v: str | None) -> str | None:
        if v is not None:
            validate_sha256_hex(v)
        return v


class PolicyInput(BaseModel):
    """The complete, immutable input to evaluate()."""

    model_config = ConfigDict(frozen=True)

    schema_version: str
    request_id: str
    now: str
    actor: Actor
    authority: AuthorityClaim
    counterparty: Counterparty
    deal: Deal
    proposal: Proposal
    content: ContentClaims | None = None
    """What the boundary's content screen said about `proposal.content_sha256`
    (ADR-0016). `None` when the proposal carries no content. Set only by the
    boundary; the engine reads it and may only narrow on it."""

    _v_request_id = field_validator("request_id")(_validate_ulid)
    _v_now = field_validator("now")(_validate_rfc3339)

    @model_validator(mode="after")
    def _content_needs_digest(self) -> PolicyInput:
        if self.content is not None and self.proposal.content_sha256 is None:
            msg = "content claims require proposal.content_sha256 (what was screened)"
            raise ValueError(msg)
        return self
