"""Operator actions on a deal (ADR-0011).

- propose: assemble the boundary claim, build an immutable PolicyInput, and run
  the single writer path (process_request). The engine decides; the console
  only renders the outcome.
- boundary: record an external (counterparty/observer) event via the transition
  table.
- approval: grant (mint + sign a one-time ApprovalRecord) or deny a pending
  approval.
- revoke: sign and store a revocation of the deal's mandate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from mandate.api import boundary
from mandate.api.deps import get_state, parse_minor, render, require_auth, require_csrf
from mandate.api.phrasing import outcome_label, reason_sentence
from mandate.api.state import AppState, Session
from mandate.application.anti_replay import GateOutcome
from mandate.application.screening import ScreenedContent, screen_content
from mandate.application.services import process_request
from mandate.crypto.signing import make_approval_record
from mandate.crypto.verification import verify_approval
from mandate.domain.authority import ActionToken, AuthorityRecord
from mandate.domain.deals import Deal, DealEvent
from mandate.domain.input import Actor, ActorKind, Counterparty, PolicyInput, Proposal
from mandate.ledger.store import (
    ApprovalDecision,
    ApprovalRequest,
    RevocationRequest,
    TransitionRequest,
)

router = APIRouter()


def _remember_screen_badge(
    state: AppState, deal_id: str, request_id: str, screened: ScreenedContent | None
) -> None:
    """Attach the screen's answer to any approval this request just opened,
    so the operator sees it beside the code-worded approval question.

    Display only — the authoritative copy is the signed MESSAGE event. The
    approval question itself is still worded by code, never by the agent
    (ADR-0011, threat-walkthrough residual #1)."""
    if screened is None:
        return
    for approval in state.store.approvals_for(deal_id):
        if approval.request_id == request_id:
            state.screen_claims[approval.approval_id] = screened.claims


def _mandate(state: AppState, deal_id: str) -> tuple[AuthorityRecord, Deal]:
    record_id = state.deal_records.get(deal_id)
    if record_id is None:
        raise HTTPException(status_code=404, detail="no mandate for this deal")
    record = state.store.get_record(record_id)
    deal = state.store.get_deal(deal_id)
    if record is None or deal is None:
        raise HTTPException(status_code=404, detail="deal or mandate not found")
    return record, deal


@router.get("/deals/{deal_id}/propose")
async def propose_form(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _s: Session = Depends(require_auth),
) -> Response:
    record, deal = _mandate(state, deal_id)
    return render(
        request,
        "propose.html",
        deal_id=deal_id,
        deal_state=deal.state.value,
        currency=record.spend_cap.currency,
        actions=[a.value for a in ActionToken],
        disclosure_fields=list(record.disclosure_fields),
        screening_on=state.screen is not None,
        error=None,
    )


@router.post("/deals/{deal_id}/propose")
async def propose(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _csrf: None = Depends(require_csrf),
) -> Response:
    record, _deal = _mandate(state, deal_id)
    form = await request.form()
    action = str(form.get("action", ""))
    try:
        ActionToken(action)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown action {action!r}") from None
    try:
        amount_minor = parse_minor(str(form.get("amount_dollars", "")) or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    # ADR-0016: the text the action would send is screened here, at the
    # boundary. Only its digest and the screen's claims reach the engine.
    content = str(form.get("content", ""))
    declared = [f.strip() for f in str(form.get("disclosure_fields", "")).split(",") if f.strip()]
    screened = screen_content(state.screen, content)

    now = boundary.now_iso()
    claim = boundary.build_claim(state, record, now=now)
    deal = state.store.get_deal(deal_id)
    assert deal is not None  # _mandate checked it
    pi = PolicyInput(
        schema_version="0.1",
        request_id=boundary.new_ulid(),
        now=now,
        actor=Actor(kind=ActorKind.AGENT, id=record.agent_id),
        authority=claim,
        counterparty=Counterparty(id=record.counterparty_id),
        deal=deal,
        proposal=Proposal(
            action=action,
            deal_id=deal_id,
            amount_minor=amount_minor,
            currency=record.spend_cap.currency,
            disclosure_fields=declared,
            idempotency_key=boundary.new_ulid(),
            content_sha256=screened.digest if screened is not None else None,
        ),
        content=screened.claims if screened is not None else None,
    )
    result = process_request(pi, state.store, state.signer, recorded_at=now)
    _remember_screen_badge(state, deal_id, pi.request_id, screened)

    decision = result.decision
    current = state.store.get_deal(deal_id)
    current_state = current.state.value if current else "?"
    blocked = result.verdict.outcome not in (GateOutcome.PASS, GateOutcome.IDEMPOTENT_HIT)
    if blocked:
        return render(
            request,
            "decision.html",
            deal_id=deal_id,
            action=action,
            outcome="Blocked by the replay gate",
            sentence=result.verdict.detail,
            current_state=current_state,
        )
    if result.verdict.outcome is GateOutcome.IDEMPOTENT_HIT:
        return render(
            request,
            "decision.html",
            deal_id=deal_id,
            action=action,
            amount_minor=amount_minor,
            currency=record.spend_cap.currency,
            outcome="Already processed",
            sentence="This exact request was already handled; the original decision stands.",
            original_outcome=outcome_label(decision.outcome) if decision else "?",
            original_reason=reason_sentence(decision.reason_code) if decision else "?",
            current_state=current_state,
        )
    assert decision is not None
    return render(
        request,
        "decision.html",
        deal_id=deal_id,
        action=action,
        amount_minor=amount_minor,
        currency=record.spend_cap.currency,
        outcome=outcome_label(decision.outcome),
        sentence=reason_sentence(decision.reason_code),
        current_state=current_state,
    )


@router.post("/deals/{deal_id}/boundary")
async def boundary_event(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _record, _deal = _mandate(state, deal_id)
    form = await request.form()
    raw = str(form.get("event", ""))
    try:
        event = DealEvent(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"unknown event {raw!r}") from None
    # ADR-0016: a counterparty note is untrusted inbound text. Screening it
    # does not gate the transition (the state machine is unchanged); it puts
    # the screen's answer in the evidence chain beside the note.
    screened = screen_content(state.screen, str(form.get("note", "")))
    now = boundary.now_iso()
    req = TransitionRequest(
        deal_id=deal_id,
        command_id=boundary.new_ulid(),
        event=event,
        actor_kind=ActorKind.SYSTEM,
        actor_id=state.operator_id,
        authority_record_id=None,
        amount_minor=None,
        occurred_at=now,
        recorded_at=now,
        note=str(form.get("note", "")),
        content_sha256=screened.digest if screened is not None else None,
        content=screened.claims if screened is not None else None,
    )
    result = state.store.commit_transition(req, state.signer)
    current = state.store.get_deal(deal_id)
    return render(
        request,
        "decision.html",
        deal_id=deal_id,
        action=f"boundary: {event.value}",
        outcome="Recorded" if result.outcome.value == "committed" else "Not applied",
        sentence=result.detail,
        current_state=current.state.value if current else "?",
    )


@router.post("/deals/{deal_id}/approvals/{approval_id}/decision")
async def decide_approval(
    request: Request,
    deal_id: str,
    approval_id: str,
    state: AppState = Depends(get_state),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _record, _deal = _mandate(state, deal_id)
    approval = state.store.get_approval(approval_id)
    if approval is None or approval.deal_id != deal_id:
        raise HTTPException(status_code=404, detail="approval not found")
    form = await request.form()
    operation = str(form.get("operation", ""))
    now = boundary.now_iso()

    if operation == ApprovalDecision.GRANTED.value:
        approval_record = make_approval_record(
            approval_record_id=boundary.new_ulid(),
            deal_id=deal_id,
            request_id=approval.request_id,
            parent_authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            currency=approval.currency,
            proposal_digest=approval.proposal_digest,
            issued_at=now,
            signer=state.signer,
        )
        check = verify_approval(
            approval_record, state.signer.public_key, expected_key_id=state.signer.key_id
        )
        if not check.valid:
            raise HTTPException(
                status_code=500, detail=f"approval record failed self-verification: {check.reason}"
            )
        req = ApprovalRequest(
            deal_id=deal_id,
            approval_id=approval_id,
            command_id=boundary.new_ulid(),
            operation=ApprovalDecision.GRANTED,
            actor_kind=ActorKind.PRINCIPAL,
            actor_id=state.operator_id,
            authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            occurred_at=now,
            recorded_at=now,
            decided_by=state.operator_id,
            approval_record=approval_record,
            deny_reason=None,
        )
    elif operation == ApprovalDecision.DENIED.value:
        req = ApprovalRequest(
            deal_id=deal_id,
            approval_id=approval_id,
            command_id=boundary.new_ulid(),
            operation=ApprovalDecision.DENIED,
            actor_kind=ActorKind.PRINCIPAL,
            actor_id=state.operator_id,
            authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            occurred_at=now,
            recorded_at=now,
            decided_by=state.operator_id,
            approval_record=None,
            deny_reason=str(form.get("deny_reason", "")) or "Denied by operator",
        )
    else:
        raise HTTPException(status_code=400, detail="operation must be granted or denied")

    state.store.commit_approval(req, state.signer)
    return RedirectResponse(f"/deals/{deal_id}", status_code=303)


@router.post("/deals/{deal_id}/revoke")
async def revoke(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _csrf: None = Depends(require_csrf),
) -> Response:
    record, _deal = _mandate(state, deal_id)
    now = boundary.now_iso()
    revocation = boundary.make_signed_revocation(state, record_id=record.record_id, now=now)
    # ADR-0014: the revocation is an authority decision — it lands on the
    # deal's chain as a signed REVOCATION event, not just in the side table.
    state.store.commit_revocation(
        RevocationRequest(
            deal_id=deal_id,
            revocation=revocation,
            command_id=boundary.new_ulid(),
            actor_kind=ActorKind.PRINCIPAL,
            actor_id=state.operator_id,
            occurred_at=now,
            recorded_at=now,
        ),
        state.signer,
    )
    return RedirectResponse(f"/deals/{deal_id}", status_code=303)
