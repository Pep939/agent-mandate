"""Pure commit plans: one code path for what a commit appends (C3).

Both ledger backends used to carry a private copy of the event-building
logic for the four commit shapes. The plans here are pure: inputs are the
stored deal, the chain head (``seq``/``prev_hash``), the request and the
signer; the output is the exact event tuple, the new deal projection and —
for approval commits — the updated approval row. No I/O, no clocks: time
enters only as the request's ``recorded_at`` (invariant 2). A backend
fetches, checks, plans, then persists; it is never a second planner.

``ApprovalDecision`` and ``grant_recheck`` live here (re-exported by
`mandate.ledger.store`) because the approval plan needs them at runtime and
`store` imports this module — the reverse direction would be a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from mandate.crypto.signing import GatewaySigner
from mandate.domain.approvals import Approval, ApprovalStatus
from mandate.domain.authority import ActionToken, AuthorityRecord, RecordStatus
from mandate.domain.deals import Deal, DealEvent, DealState, apply_event
from mandate.domain.decisions import Outcome
from mandate.domain.events import Event, EventType
from mandate.domain.lifecycle import resolve_status
from mandate.domain.state_machine import ACTION_EVENTS, apply_action, transition_for
from mandate.ledger.chain import build_event, make_event_id
from mandate.ledger.payloads import (
    approval_payload,
    decision_payload,
    message_payload,
    revocation_payload,
    transition_payload,
)

if TYPE_CHECKING:
    from mandate.ledger.store import (
        ApprovalRequest,
        CommitRequest,
        RevocationRequest,
        TransitionRequest,
    )

__all__ = [
    "ApprovalDecision",
    "CommitPlan",
    "grant_recheck",
    "plan_commit_approval",
    "plan_commit_request",
    "plan_commit_revocation",
    "plan_commit_transition",
]


def grant_recheck(
    record: AuthorityRecord | None,
    revoked: bool,
    deal: Deal,
    token: ActionToken,
    occurred_at: str,
) -> tuple[str | None, DealEvent | None]:
    """ADR-0010 steps 2-3: the rechecks a grant must pass before it applies
    its transition (invariant 3, at decision time; invariant 7).

    Returns ``(forced_deny, event)``: a non-None ``forced_deny`` means the
    grant must become a logged deny — the parent authority is no longer
    current (revoked, expired, missing) or the stored deal no longer permits
    the transition; otherwise ``event`` is the transition the grant applies.
    """
    if record is None:
        return (
            "parent authority record is missing from the ledger; "
            "the grant is denied and the approval is closed",
            None,
        )
    status = resolve_status(record, occurred_at, revoked=revoked)
    if status is not RecordStatus.ACTIVE:
        return (
            f"parent authority is no longer current at decision time "
            f"({status.value}); the grant is denied and the approval is closed",
            None,
        )
    event = ACTION_EVENTS[token]
    if event is None or transition_for(deal.state, event) is None:
        return (
            f"transition is no longer valid: {token.value!r} cannot be applied from "
            f"stored state {deal.state.value}; the grant is denied and the approval is closed",
            None,
        )
    return None, event


class ApprovalDecision(StrEnum):
    """The operator's call on one pending approval (ADR-0010)."""

    GRANTED = "granted"
    DENIED = "denied"


@dataclass(frozen=True)
class CommitPlan:
    """What a commit will persist: the events to append (chain order), the
    deal projection they imply, and the approval row to insert/update."""

    events: tuple[Event, ...]
    new_deal: Deal
    approval: Approval | None = None


def plan_commit_request(
    deal: Deal,
    seq: int,
    prev_hash: str,
    req: CommitRequest,
    event: DealEvent | None,
    signer: GatewaySigner,
) -> CommitPlan:
    """The policy-outcome commit: the policy_decision event (always —
    invariant 5), plus the state_transition event on an ALLOWed transition,
    or the pending-approval row + approval event on NEEDS_APPROVAL.
    ``event`` is the `plan_transition` result; callers abort on stale state
    before planning.

    When the request carried content (ADR-0016), a MESSAGE event — the
    content digest and the screen's claims — is appended *first*, so the
    chain records what was screened before what was decided."""
    built: list[Event] = []
    if req.content is not None and req.content_sha256 is not None:
        built.append(
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq,
                event_type=EventType.MESSAGE,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=prev_hash,
                payload=message_payload(
                    direction="outbound",
                    content_sha256=req.content_sha256,
                    claims=req.content,
                    request_id=req.request_id,
                    action=req.action,
                    declared_fields=req.declared_fields,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            )
        )
        seq += 1
        prev_hash = built[-1].event_hash
    built.append(
        build_event(
            event_id=make_event_id(req.recorded_at),
            deal_id=req.deal_id,
            sequence_number=seq,
            event_type=EventType.POLICY_DECISION,
            actor_kind=req.actor_kind,
            actor_id=req.actor_id,
            authority_record_id=req.authority_record_id,
            previous_event_hash=prev_hash,
            payload=decision_payload(
                request_id=req.request_id,
                action=req.action,
                decision=req.decision,
                amount_minor=req.amount_minor,
                idempotency_key=req.idempotency_key,
                proposal_digest=req.proposal_digest,
            ),
            occurred_at=req.occurred_at,
            recorded_at=req.recorded_at,
            signer=signer,
        )
    )
    decision_event = built[-1]
    new_deal = deal
    if event is not None:
        new_deal = apply_action(deal, ActionToken(req.action), req.amount_minor)
        built.append(
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq + 1,
                event_type=EventType.STATE_TRANSITION,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=decision_event.event_hash,
                payload=transition_payload(
                    request_id=req.request_id,
                    command_id=None,
                    action=req.action,
                    event=event,
                    deal=deal,
                    new_deal=new_deal,
                    amount_minor=req.amount_minor,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            )
        )

    approval: Approval | None = None
    if req.decision.outcome is Outcome.NEEDS_APPROVAL:
        approval = Approval(
            approval_id=make_event_id(req.recorded_at),
            deal_id=req.deal_id,
            request_id=req.request_id,
            authority_record_id=req.authority_record_id,
            action=req.action,
            amount_minor=req.amount_minor,
            currency=req.record.spend_cap.currency,
            proposal_digest=req.proposal_digest,
            reason_code=req.decision.reason_code,
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_at=None,
            command_id=None,
            created_at=req.recorded_at,
        )
        new_deal = deal.model_copy(update={"open_approvals": deal.open_approvals + 1})
        built.append(
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq + 1,
                event_type=EventType.APPROVAL,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=decision_event.event_hash,
                payload=approval_payload(
                    operation="required",
                    request_id=req.request_id,
                    action=req.action,
                    amount_minor=req.amount_minor,
                    approval_id=approval.approval_id,
                    currency=req.record.spend_cap.currency,
                    authority_record_id=req.authority_record_id,
                    reason_code=req.decision.reason_code.value,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            )
        )
    return CommitPlan(tuple(built), new_deal, approval)


def plan_commit_transition(
    deal: Deal,
    seq: int,
    prev_hash: str,
    req: TransitionRequest,
    target: DealState,
    signer: GatewaySigner,
) -> CommitPlan:
    """A boundary/operator transition (ADR-0009): one state_transition event
    to the ``target`` state. Callers check `transition_for` before planning.

    When the counterparty note was screened (ADR-0016), an inbound MESSAGE
    event precedes the transition. The transition itself is unchanged —
    the screen is evidence here, not a gate."""
    new_deal = apply_event(deal, req.event, target, req.amount_minor)
    built: list[Event] = []
    if req.content is not None and req.content_sha256 is not None:
        built.append(
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq,
                event_type=EventType.MESSAGE,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=prev_hash,
                payload=message_payload(
                    direction="inbound",
                    content_sha256=req.content_sha256,
                    claims=req.content,
                    command_id=req.command_id,
                    event=req.event.value,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            )
        )
        seq += 1
        prev_hash = built[-1].event_hash
    built.append(
        build_event(
            event_id=make_event_id(req.recorded_at),
            deal_id=req.deal_id,
            sequence_number=seq,
            event_type=EventType.STATE_TRANSITION,
            actor_kind=req.actor_kind,
            actor_id=req.actor_id,
            authority_record_id=req.authority_record_id,
            previous_event_hash=prev_hash,
            payload=transition_payload(
                request_id=None,
                command_id=req.command_id,
                action=None,
                event=req.event,
                deal=deal,
                new_deal=new_deal,
                amount_minor=req.amount_minor,
                note=req.note,
            ),
            occurred_at=req.occurred_at,
            recorded_at=req.recorded_at,
            signer=signer,
        )
    )
    return CommitPlan(tuple(built), new_deal, None)


def plan_commit_approval(
    deal: Deal,
    approval: Approval,
    seq: int,
    prev_hash: str,
    req: ApprovalRequest,
    record: AuthorityRecord | None,
    revoked: bool,
    token: ActionToken | None,
    signer: GatewaySigner,
) -> CommitPlan:
    """Decide one pending approval (ADR-0010). A grant rechecks before it
    applies its transition (invariant 3 at decision time; invariant 7 via
    ``grant_recheck``); a forced deny or an operator deny appends the single
    approval event. ``record``/``revoked``/``token`` are the backend's grant
    inputs — fetched only when the operation is GRANTED."""
    operation = req.operation
    forced_deny: str | None = None
    event: DealEvent | None = None
    if operation is ApprovalDecision.GRANTED:
        if req.approval_record is None:
            msg = "grant requires a signed approval record"
            raise ValueError(msg)
        assert token is not None  # backend parsed (or aborted on unknown action)
        forced_deny, event = grant_recheck(record, revoked, deal, token, req.occurred_at)
        if forced_deny is not None:
            operation = ApprovalDecision.DENIED

    if operation is ApprovalDecision.GRANTED:
        assert token is not None and event is not None  # set above
        new_deal = apply_action(deal, token, req.amount_minor)
        new_deal = new_deal.model_copy(
            update={"open_approvals": max(0, new_deal.open_approvals - 1)}
        )
        approval_event = build_event(
            event_id=make_event_id(req.recorded_at),
            deal_id=req.deal_id,
            sequence_number=seq,
            event_type=EventType.APPROVAL,
            actor_kind=req.actor_kind,
            actor_id=req.actor_id,
            authority_record_id=req.authority_record_id,
            previous_event_hash=prev_hash,
            payload=approval_payload(
                operation="granted",
                request_id=approval.request_id,
                action=req.action,
                amount_minor=req.amount_minor,
                command_id=req.command_id,
                decided_by=req.decided_by,
                approval_record=req.approval_record,
            ),
            occurred_at=req.occurred_at,
            recorded_at=req.recorded_at,
            signer=signer,
        )
        built: tuple[Event, ...] = (
            approval_event,
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq + 1,
                event_type=EventType.STATE_TRANSITION,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=approval_event.event_hash,
                payload=transition_payload(
                    request_id=approval.request_id,
                    command_id=None,
                    action=req.action,
                    event=event,
                    deal=deal,
                    new_deal=new_deal,
                    amount_minor=req.amount_minor,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            ),
        )
    else:
        new_deal = deal.model_copy(update={"open_approvals": max(0, deal.open_approvals - 1)})
        built = (
            build_event(
                event_id=make_event_id(req.recorded_at),
                deal_id=req.deal_id,
                sequence_number=seq,
                event_type=EventType.APPROVAL,
                actor_kind=req.actor_kind,
                actor_id=req.actor_id,
                authority_record_id=req.authority_record_id,
                previous_event_hash=prev_hash,
                payload=approval_payload(
                    operation="denied",
                    request_id=approval.request_id,
                    action=req.action,
                    amount_minor=req.amount_minor,
                    command_id=req.command_id,
                    decided_by=req.decided_by,
                    deny_reason=forced_deny if forced_deny is not None else req.deny_reason,
                ),
                occurred_at=req.occurred_at,
                recorded_at=req.recorded_at,
                signer=signer,
            ),
        )

    decided = approval.model_copy(
        update={
            "status": ApprovalStatus(operation.value),
            "decided_by": req.decided_by,
            "decided_at": req.recorded_at,
            "command_id": req.command_id,
        }
    )
    return CommitPlan(built, new_deal, decided)


def plan_commit_revocation(
    deal: Deal,
    seq: int,
    prev_hash: str,
    req: RevocationRequest,
    signer: GatewaySigner,
) -> CommitPlan:
    """One revocation event on the linked deal's chain (ADR-0014); the deal
    projection is unchanged."""
    event = build_event(
        event_id=make_event_id(req.recorded_at),
        deal_id=req.deal_id,
        sequence_number=seq,
        event_type=EventType.REVOCATION,
        actor_kind=req.actor_kind,
        actor_id=req.actor_id,
        authority_record_id=req.revocation.record_id,
        previous_event_hash=prev_hash,
        payload=revocation_payload(revocation=req.revocation),
        occurred_at=req.occurred_at,
        recorded_at=req.recorded_at,
        signer=signer,
    )
    return CommitPlan((event,), deal, None)
