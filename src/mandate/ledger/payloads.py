"""Event payload builders (ADR-0009).

Payloads carry structured, non-sensitive data and digests — never raw
counterparty text, LLM output or secrets (brief §13, invariant 11/12).
"""

from __future__ import annotations

from mandate.domain.approvals import ApprovalRecord
from mandate.domain.authority import Revocation
from mandate.domain.content import ContentClaims
from mandate.domain.deals import Deal, DealEvent
from mandate.domain.decisions import PolicyDecision

__all__ = [
    "approval_payload",
    "decision_payload",
    "message_payload",
    "revocation_payload",
    "transition_payload",
]


def message_payload(
    *,
    direction: str,
    content_sha256: str,
    claims: ContentClaims,
    request_id: str | None = None,
    command_id: str | None = None,
    action: str | None = None,
    event: str | None = None,
    declared_fields: list[str] | None = None,
) -> dict[str, object]:
    """The message payload (``EventType.MESSAGE``, ADR-0016): the digest of
    the content plus the content screen's full answer — never the text.

    ``direction`` is ``outbound`` (an agent proposal's content, keyed by
    ``request_id`` + ``action``) or ``inbound`` (a counterparty note, keyed by
    ``command_id`` + ``event``). ``declared_fields`` is what the agent said
    it would disclose, kept beside what the screen detected so a reviewer
    sees the comparison in the chain."""
    if direction not in ("outbound", "inbound"):
        msg = f"direction must be outbound or inbound: {direction!r}"
        raise ValueError(msg)
    payload: dict[str, object] = {
        "direction": direction,
        "content_sha256": content_sha256,
        "screen": claims.model_dump(mode="json"),
    }
    if direction == "outbound":
        payload["request_id"] = request_id
        payload["action"] = action
        payload["declared_fields"] = list(declared_fields or ())
    else:
        payload["command_id"] = command_id
        payload["event"] = event
    return payload


def decision_payload(
    *,
    request_id: str,
    action: str,
    decision: PolicyDecision,
    amount_minor: int | None,
    idempotency_key: str,
    proposal_digest: str,
) -> dict[str, object]:
    """The policy_decision payload: the full decision plus request refs.

    The proposal itself is represented by its canonical digest only.
    """
    return {
        "request_id": request_id,
        "action": action,
        "outcome": decision.outcome.value,
        "reason_code": decision.reason_code.value,
        "explanation": decision.explanation,
        "matched_rule": decision.matched_rule,
        "evaluated_at": decision.evaluated_at,
        "input_digest": decision.input_digest,
        "amount_minor": amount_minor,
        "idempotency_key": idempotency_key,
        "proposal_digest": proposal_digest,
    }


def transition_payload(
    *,
    request_id: str | None,
    command_id: str | None,
    action: str | None,
    event: DealEvent,
    deal: Deal,
    new_deal: Deal,
    amount_minor: int | None,
    note: str = "",
) -> dict[str, object]:
    """The state_transition payload. Exactly one of request_id (action path)
    or command_id (boundary path) is set."""
    payload: dict[str, object] = {
        "event": event.value,
        "from_state": deal.state.value,
        "to_state": new_deal.state.value,
        "amount_minor": amount_minor,
    }
    if request_id is not None:
        payload["request_id"] = request_id
        payload["action"] = action
    else:
        payload["command_id"] = command_id
        if note:
            payload["note"] = note
    return payload


def approval_payload(
    *,
    operation: str,
    request_id: str,
    action: str,
    amount_minor: int | None,
    approval_id: str | None = None,
    currency: str | None = None,
    authority_record_id: str | None = None,
    reason_code: str | None = None,
    command_id: str | None = None,
    decided_by: str | None = None,
    deny_reason: str | None = None,
    approval_record: ApprovalRecord | None = None,
) -> dict[str, object]:
    """The approval payload (``EventType.APPROVAL``). ``operation`` is one of
    ``required`` | ``granted`` | ``denied`` (ADR-0010). On grant it carries the
    signed ``ApprovalRecord`` — public data, never a secret (invariant 12)."""
    payload: dict[str, object] = {
        "operation": operation,
        "request_id": request_id,
        "action": action,
        "amount_minor": amount_minor,
    }
    if operation == "required":
        payload["approval_id"] = approval_id
        payload["currency"] = currency
        payload["authority_record_id"] = authority_record_id
        payload["reason_code"] = reason_code
    else:
        payload["command_id"] = command_id
        payload["decided_by"] = decided_by
        if operation == "granted":
            if approval_record is None:
                msg = "granted approval payload requires a signed approval record"
                raise ValueError(msg)
            payload["approval_record"] = approval_record.model_dump(mode="json")
        elif operation == "denied" and deny_reason is not None:
            payload["deny_reason"] = deny_reason
    return payload


def revocation_payload(*, revocation: Revocation) -> dict[str, object]:
    """The revocation payload (``EventType.REVOCATION``, ADR-0014): the signed
    ``Revocation`` record itself — public data, never a secret (invariant 12).
    ``verify_revocation`` runs on it unchanged."""
    return {"revocation": revocation.model_dump(mode="json")}
