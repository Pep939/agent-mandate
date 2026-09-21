"""Deal listing and detail screens (ADR-0011).

The home page lists the deals this console knows about (a boundary-side
registry — a single-operator local console drives all deals it shows). The
detail page shows the live state, open approvals, and the action forms.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import RedirectResponse, Response

from mandate.api import boundary
from mandate.api.deps import get_state, render, require_auth, require_csrf
from mandate.api.state import AppState, Session
from mandate.domain.approvals import Approval, ApprovalStatus
from mandate.domain.deals import DealEvent
from mandate.domain.lifecycle import resolve_status

router = APIRouter()


@dataclass(frozen=True)
class ScreenBadge:
    """What the deal page shows about one screened message (ADR-0016)."""

    screener: str
    available: bool
    detected: list[str]
    hostility_pct: int
    persuasion_pct: int
    urgency: int
    urgency_label: str


@dataclass(frozen=True)
class ApprovalRow:
    """A pending approval plus its content-screen badge, if any."""

    approval: Approval
    screen: ScreenBadge | None


@router.get("/")
async def home(
    request: Request, state: AppState = Depends(get_state), _s: Session = Depends(require_auth)
) -> Response:
    now = boundary.now_iso()
    rows = []
    for deal_id in state.deal_ids:
        deal = state.store.get_deal(deal_id)
        if deal is None:
            continue
        record_id = state.deal_records.get(deal_id)
        record = state.store.get_record(record_id) if record_id else None
        mandate_state = "?"
        if record is not None:
            mandate_state = resolve_status(
                record, now, revoked=_is_revoked(state, deal_id, now)
            ).value
        pending = [
            a for a in state.store.approvals_for(deal_id) if a.status is ApprovalStatus.PENDING
        ]
        rows.append(
            {
                "id": deal_id,
                "state": deal.state.value,
                "committed_minor": deal.committed_minor,
                "mandate_state": mandate_state,
                "open_approvals": len(pending),
            }
        )
    return render(request, "home.html", deals=rows)


_URGENCY_LABELS = ("no time pressure", "soon", "today", "emergency")


def _screen_badge(state: AppState, approval_id: str) -> ScreenBadge | None:
    """The screen's summary for one pending approval, shaped for the template.

    Everything here is derived from the integers the screen produced; no
    agent or counterparty text is ever rendered (invariant 11, ADR-0011)."""
    claims = state.screen_claims.get(approval_id)
    if claims is None:
        return None
    return ScreenBadge(
        screener=claims.screener,
        available=claims.available,
        detected=[f"{d.field} ({d.confidence_bp // 100}%)" for d in claims.detected],
        hostility_pct=claims.hostility_bp // 100,
        persuasion_pct=claims.persuasion_bp // 100,
        urgency=claims.urgency_level,
        urgency_label=_URGENCY_LABELS[claims.urgency_level],
    )


def _is_revoked(state: AppState, deal_id: str, now: str) -> bool:
    record_id = state.deal_records.get(deal_id)
    if record_id is None:
        return False
    return len(state.store.list_revocations([record_id])) > 0


@router.post("/deals/new")
async def new_deal(
    request: Request,
    state: AppState = Depends(get_state),
    _csrf: None = Depends(require_csrf),
) -> Response:
    now = boundary.now_iso()
    deal_id = boundary.new_ulid()
    record = boundary.make_default_record(state, now, "Operator-created mandate")
    boundary.register_deal(state, deal_id, record, now)
    return RedirectResponse(f"/deals/{deal_id}", status_code=303)


@router.get("/deals/{deal_id}")
async def deal_detail(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _s: Session = Depends(require_auth),
) -> Response:
    deal = state.store.get_deal(deal_id)
    if deal is None:
        raise HTTPException(status_code=404, detail="deal not found")
    now = boundary.now_iso()
    record_id = state.deal_records.get(deal_id)
    record = state.store.get_record(record_id) if record_id else None
    mandate_state = "?"
    if record is not None:
        mandate_state = resolve_status(record, now, revoked=_is_revoked(state, deal_id, now)).value
    pending = [a for a in state.store.approvals_for(deal_id) if a.status is ApprovalStatus.PENDING]
    # ADR-0016: the content screen's answer rides beside each approval, and
    # the most urgent ones sort first. Advisory: it changes the order and
    # adds a badge, never the approval question, which stays code-worded.
    rows = [ApprovalRow(approval=a, screen=_screen_badge(state, a.approval_id)) for a in pending]
    rows.sort(key=lambda r: -(r.screen.urgency if r.screen is not None else 0))
    return render(
        request,
        "deal.html",
        deal_id=deal_id,
        deal=deal,
        mandate_state=mandate_state,
        approvals=rows,
        boundary_events=[e.value for e in DealEvent],
        screening_on=state.screen is not None,
    )


@router.get("/deals/{deal_id}/timeline")
async def timeline(
    request: Request,
    deal_id: str,
    state: AppState = Depends(get_state),
    _s: Session = Depends(require_auth),
) -> Response:
    deal = state.store.get_deal(deal_id)
    if deal is None:
        raise HTTPException(status_code=404, detail="deal not found")
    events = [
        {
            "seq": e.sequence_number,
            "type": e.event_type.value,
            "actor": e.actor_kind.value,
            "actor_id": e.actor_id,
            "occurred_at": e.occurred_at,
            "payload": e.payload,
        }
        for e in state.store.events_for(deal_id)
    ]
    return render(
        request, "timeline.html", deal_id=deal_id, deal_state=deal.state.value, events=events
    )
