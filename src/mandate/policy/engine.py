"""Pure policy evaluation: PolicyDecision = evaluate(PolicyInput).

Thirteen-step evaluation order per specs/policy-schema.md, plus the two
ADR-0016 content-screen steps (9b deny, 12b hold) that read the boundary's
`ContentClaims` and may only narrow.
No I/O, no model calls, no clock calls, no network (invariant 2): a screen's
claims arrive as an immutable input, like `signature_valid`.
"""

from __future__ import annotations

from datetime import datetime

from mandate.crypto.canonicalization import canonical_sha256_hex
from mandate.domain.authority import ActionToken, RecordStatus
from mandate.domain.decisions import Outcome, PolicyDecision, ReasonCode
from mandate.domain.input import PolicyInput
from mandate.domain.state_machine import (
    ACTION_VALID_STATES,
    NEGOTIATION_ACTIONS,
    PAYMENT_ACTIONS,
)

SUPPORTED_SCHEMA_VERSION = "0.1"

# ADR-0016 content-screen thresholds, in basis points. Tuned per pinned
# screener version; a change here is a new ADR, never a silent edit.
CONTENT_DENY_BP = 9_000
"""A detected, undeclared sensitive field at or above this → DENY (step 9b)."""
CONTENT_HOLD_BP = 7_000
"""Between HOLD and DENY, or hostility at/above HOLD → NEEDS_APPROVAL (step 12b)."""


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _input_digest(pi: PolicyInput) -> str:
    """SHA-256 over the shared canonical form (invariant 13, ADR-0005)."""
    return canonical_sha256_hex(pi.model_dump(mode="json"))


def _decision(
    pi: PolicyInput,
    digest: str,
    outcome: Outcome,
    reason: ReasonCode,
    rule: str,
    explanation: str,
) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,
        reason_code=reason,
        explanation=explanation,
        matched_rule=rule,
        authority_record_id=pi.authority.record.record_id,
        evaluated_at=pi.now,
        input_digest=digest,
    )


def _deny(
    pi: PolicyInput, digest: str, reason: ReasonCode, rule: str, explanation: str
) -> PolicyDecision:
    return _decision(pi, digest, Outcome.DENY, reason, rule, explanation)


def _needs_approval(
    pi: PolicyInput, digest: str, reason: ReasonCode, rule: str, explanation: str
) -> PolicyDecision:
    return _decision(pi, digest, Outcome.NEEDS_APPROVAL, reason, rule, explanation)


def evaluate(pi: PolicyInput) -> PolicyDecision:  # noqa: C901
    """Evaluate a policy input and return a decision.

    Deterministic: same input bytes always produce same decision bytes.
    Never raises on well-typed input; unknown pairs deny.
    """
    digest = _input_digest(pi)
    record = pi.authority.record
    proposal = pi.proposal
    deal = pi.deal

    # Step 1: schema version
    if pi.schema_version != SUPPORTED_SCHEMA_VERSION:
        return _deny(
            pi,
            digest,
            ReasonCode.UNKNOWN_SCHEMA_VERSION,
            "step_01_schema_version",
            f"Unsupported schema version {pi.schema_version!r}; "
            f"engine supports {SUPPORTED_SCHEMA_VERSION!r}",
        )

    # Step 2: signature claim
    if not pi.authority.signature_valid:
        return _deny(
            pi,
            digest,
            ReasonCode.INVALID_SIGNATURE_CLAIM,
            "step_02_signature",
            "Boundary reports signature claim is invalid",
        )

    # Step 3: validity interval + revocation
    if pi.authority.status is RecordStatus.REVOKED:
        return _deny(
            pi,
            digest,
            ReasonCode.RECORD_REVOKED,
            "step_03_validity",
            "Authority record has been revoked",
        )
    if pi.authority.status is RecordStatus.EXPIRED:
        return _deny(
            pi,
            digest,
            ReasonCode.RECORD_EXPIRED,
            "step_03_validity",
            "Authority record has expired",
        )
    now = _parse_ts(pi.now)
    if now < _parse_ts(record.not_before):
        return _deny(
            pi,
            digest,
            ReasonCode.NOT_YET_VALID,
            "step_03_validity",
            f"Evaluation time is before record not_before {record.not_before}",
        )
    if now > _parse_ts(record.expires_at):
        return _deny(
            pi,
            digest,
            ReasonCode.RECORD_EXPIRED,
            "step_03_validity",
            f"Evaluation time is past record expires_at {record.expires_at}",
        )

    # Step 4: delegation chain
    for link in pi.authority.delegation_chain:
        if not link.scope_narrowing_valid:
            return _deny(
                pi,
                digest,
                ReasonCode.DELEGATION_CHAIN_BROKEN,
                "step_04_delegation",
                f"Delegation link {link.parent_record_id} has invalid scope narrowing",
            )

    # Step 5: audience / counterparty
    if (
        record.counterparty_id is not None
        and pi.counterparty.id is not None
        and pi.counterparty.id != record.counterparty_id
    ):
        return _deny(
            pi,
            digest,
            ReasonCode.AUDIENCE_MISMATCH,
            "step_05_audience",
            f"Counterparty {pi.counterparty.id} does not match "
            f"record audience {record.counterparty_id}",
        )

    # Step 6: prohibited actions (invariant 6: prohibition beats allowance)
    action_str = proposal.action
    if action_str in {a.value for a in record.prohibited_actions}:
        return _deny(
            pi,
            digest,
            ReasonCode.ACTION_PROHIBITED,
            "step_06_prohibited",
            f"Action {action_str!r} is explicitly prohibited by the mandate",
        )

    # Step 7: action must be a known token AND in allowed_actions
    try:
        action = ActionToken(action_str)
    except ValueError:
        return _deny(
            pi,
            digest,
            ReasonCode.UNKNOWN_ACTION,
            "step_07_allowed",
            f"Action {action_str!r} is not in the closed vocabulary",
        )
    if action not in record.allowed_actions:
        return _deny(
            pi,
            digest,
            ReasonCode.ACTION_NOT_ALLOWED,
            "step_07_allowed",
            f"Action {action_str!r} is not in the mandate's allowed_actions",
        )

    # Step 8: state transition + payment blocks (invariant 10)
    valid_states = ACTION_VALID_STATES.get(action, frozenset())
    if deal.state not in valid_states:
        return _deny(
            pi,
            digest,
            ReasonCode.INVALID_TRANSITION,
            "step_08_transition",
            f"Action {action_str!r} is not valid from state {deal.state.value}",
        )
    if action in PAYMENT_ACTIONS:
        if deal.open_disputes > 0:
            return _deny(
                pi,
                digest,
                ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE,
                "step_08_transition",
                f"Payment blocked: {deal.open_disputes} open dispute(s)",
            )
        if deal.open_approvals > 0:
            return _deny(
                pi,
                digest,
                ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL,
                "step_08_transition",
                f"Payment blocked: {deal.open_approvals} open approval(s)",
            )

    # Step 9: disclosure allow-list (invariant 9)
    for field in proposal.disclosure_fields:
        if field not in record.disclosure_fields:
            return _deny(
                pi,
                digest,
                ReasonCode.DISCLOSURE_NOT_ALLOWED,
                "step_09_disclosure",
                f"Disclosure field {field!r} is not in the mandate's allow-list",
            )

    # Step 9b: content screen — a detected, undeclared sensitive field the
    # screen is near-certain about denies (ADR-0016; closes threat-model G1).
    # The screen only ever narrows: nothing in this step can allow.
    if pi.content is not None:
        for leak in pi.content.undeclared(record.disclosure_fields):
            if leak.confidence_bp >= CONTENT_DENY_BP:
                return _deny(
                    pi,
                    digest,
                    ReasonCode.DISCLOSURE_DETECTED,
                    "step_09b_content_disclosure",
                    f"Content screen detected undeclared field {leak.field!r} "
                    f"({leak.confidence_bp} bp) not in the mandate's allow-list",
                )

    # Step 10: financial exposure (currency check precedes cap comparison)
    if proposal.amount_minor is not None:
        if proposal.currency != record.spend_cap.currency:
            return _deny(
                pi,
                digest,
                ReasonCode.CURRENCY_MISMATCH,
                "step_10_spend",
                f"Proposal currency {proposal.currency!r} does not match "
                f"spend cap currency {record.spend_cap.currency!r}",
            )
        total = deal.committed_minor + proposal.amount_minor
        if total > record.spend_cap.amount_minor:
            return _needs_approval(
                pi,
                digest,
                ReasonCode.SPEND_CAP_EXCEEDED,
                "step_10_spend",
                f"Cumulative spend {total} exceeds cap "
                f"{record.spend_cap.amount_minor} {record.spend_cap.currency}",
            )

    # Step 11: negotiation limits
    if action in NEGOTIATION_ACTIONS and deal.negotiated_rounds >= record.max_negotiation_rounds:
        return _deny(
            pi,
            digest,
            ReasonCode.NEGOTIATION_LIMIT_REACHED,
            "step_11_limits",
            f"Negotiation rounds {deal.negotiated_rounds} reached cap "
            f"{record.max_negotiation_rounds}",
        )

    # Step 12: human approval requirement
    if action in record.requires_human_approval_for:
        return _needs_approval(
            pi,
            digest,
            ReasonCode.APPROVAL_REQUIRED,
            "step_12_approval",
            f"Action {action_str!r} requires human approval per the mandate",
        )

    # Step 12b: content screen holds (ADR-0016). Anything the screen could
    # not vouch for goes to a person: an unavailable screen (outage, timeout),
    # a probable-but-not-certain leak, or probable hostile content. Never an
    # allow — this step only turns an allow into a hold.
    if pi.content is not None:
        if not pi.content.available:
            return _needs_approval(
                pi,
                digest,
                ReasonCode.CONTENT_SCREEN_UNAVAILABLE,
                "step_12b_content_hold",
                "Content screen was unavailable; a person must review the content",
            )
        for leak in pi.content.undeclared(record.disclosure_fields):
            if leak.confidence_bp >= CONTENT_HOLD_BP:
                return _needs_approval(
                    pi,
                    digest,
                    ReasonCode.CONTENT_REVIEW_REQUIRED,
                    "step_12b_content_hold",
                    f"Content screen suspects undeclared field {leak.field!r} "
                    f"({leak.confidence_bp} bp); a person must review the content",
                )
        if pi.content.hostility_bp >= CONTENT_HOLD_BP:
            return _needs_approval(
                pi,
                digest,
                ReasonCode.HOSTILE_CONTENT_SUSPECTED,
                "step_12b_content_hold",
                f"Content screen suspects hostile content ({pi.content.hostility_bp} bp); "
                "a person must review it",
            )

    # Step 13: allow
    return _decision(
        pi,
        digest,
        Outcome.ALLOW,
        ReasonCode.OK,
        "step_13_allow",
        "All checks passed",
    )
