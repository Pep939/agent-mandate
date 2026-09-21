"""Policy decision output model."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class ReasonCode(StrEnum):
    OK = "ok"
    UNKNOWN_SCHEMA_VERSION = "unknown_schema_version"
    MISSING_FIELD = "missing_field"
    INVALID_SIGNATURE_CLAIM = "invalid_signature_claim"
    RECORD_REVOKED = "record_revoked"
    RECORD_EXPIRED = "record_expired"
    NOT_YET_VALID = "not_yet_valid"
    DELEGATION_CHAIN_BROKEN = "delegation_chain_broken"
    AUDIENCE_MISMATCH = "audience_mismatch"
    REPLAY_DETECTED = "replay_detected"
    ACTION_PROHIBITED = "action_prohibited"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    UNKNOWN_ACTION = "unknown_action"
    INVALID_TRANSITION = "invalid_transition"
    DISCLOSURE_NOT_ALLOWED = "disclosure_not_allowed"
    SPEND_CAP_EXCEEDED = "spend_cap_exceeded"
    NEGOTIATION_LIMIT_REACHED = "negotiation_limit_reached"
    APPROVAL_REQUIRED = "approval_required"
    PAYMENT_BLOCKED_BY_DISPUTE = "payment_blocked_by_dispute"
    PAYMENT_BLOCKED_BY_OPEN_APPROVAL = "payment_blocked_by_open_approval"
    CURRENCY_MISMATCH = "currency_mismatch"
    # ADR-0016 content screen (narrowing only: these never accompany ALLOW)
    DISCLOSURE_DETECTED = "disclosure_detected"
    CONTENT_REVIEW_REQUIRED = "content_review_required"
    HOSTILE_CONTENT_SUSPECTED = "hostile_content_suspected"
    CONTENT_SCREEN_UNAVAILABLE = "content_screen_unavailable"


class PolicyDecision(BaseModel):
    """Immutable output of a single policy evaluation."""

    model_config = ConfigDict(frozen=True)

    outcome: Outcome
    reason_code: ReasonCode
    explanation: str
    matched_rule: str
    authority_record_id: str
    evaluated_at: str
    input_digest: str
