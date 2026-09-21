"""Deal state and event enums, plus the deal snapshot model."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from mandate.domain.authority import _validate_ulid


class DealState(StrEnum):
    DRAFT = "DRAFT"
    QUOTE_REQUESTED = "QUOTE_REQUESTED"
    QUOTE_RECEIVED = "QUOTE_RECEIVED"
    NEGOTIATING = "NEGOTIATING"
    AGREED = "AGREED"
    IN_PROGRESS = "IN_PROGRESS"
    CHANGE_REQUESTED = "CHANGE_REQUESTED"
    COMPLETED = "COMPLETED"
    ACCEPTANCE_WINDOW = "ACCEPTANCE_WINDOW"
    DISPUTED = "DISPUTED"
    ACCEPTED = "ACCEPTED"
    PAYMENT_PENDING = "PAYMENT_PENDING"
    CAPTURED = "CAPTURED"
    PARTIALLY_REFUNDED = "PARTIALLY_REFUNDED"
    REFUNDED = "REFUNDED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class DealEvent(StrEnum):
    QUOTE_REQUESTED = "quote_requested"
    QUOTE_RECEIVED = "quote_received"
    COUNTEROFFERED = "counteroffered"
    AGREEMENT_REACHED = "agreement_reached"
    WORK_STARTED = "work_started"
    CHANGE_REQUESTED = "change_requested"
    CHANGE_APPROVED = "change_approved"
    CHANGE_REJECTED = "change_rejected"
    COMPLETION_CLAIMED = "completion_claimed"
    ACCEPTANCE_WINDOW_OPENED = "acceptance_window_opened"
    ACCEPTED = "accepted"
    DISPUTE_OPENED = "dispute_opened"
    PAYMENT_INITIATED = "payment_initiated"
    PAYMENT_CONFIRMED = "payment_confirmed"
    PAYMENT_FAILED = "payment_failed"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    RESUMED = "resumed"


class Deal(BaseModel):
    """Immutable snapshot of a deal at evaluation time."""

    model_config = ConfigDict(frozen=True)

    deal_id: str
    state: DealState
    negotiated_rounds: int = 0
    committed_minor: int = 0
    open_disputes: int = 0
    open_approvals: int = 0

    _v_deal_id = field_validator("deal_id")(_validate_ulid)


def apply_event(
    deal: Deal, event: DealEvent, target_state: DealState, amount_minor: int | None = None
) -> Deal:
    """The deal after one event, with the ADR-0009 counter table.

    Pure and table-driven. The target state is computed by the caller
    (state_machine.transition_for) so this module keeps no import of
    state_machine (the enum import direction is one-way).
    """
    rounds = deal.negotiated_rounds
    committed = deal.committed_minor
    disputes = deal.open_disputes
    if event is DealEvent.COUNTEROFFERED:
        rounds += 1
    elif event in (DealEvent.AGREEMENT_REACHED, DealEvent.CHANGE_APPROVED):
        committed += amount_minor if amount_minor is not None else 0
    elif event is DealEvent.DISPUTE_OPENED:
        disputes += 1
    elif event is DealEvent.ACCEPTED and deal.state is DealState.DISPUTED:
        disputes = max(0, disputes - 1)
    elif event in (DealEvent.REFUNDED, DealEvent.PARTIALLY_REFUNDED):
        disputes = 0
    return deal.model_copy(
        update={
            "state": target_state,
            "negotiated_rounds": rounds,
            "committed_minor": committed,
            "open_disputes": disputes,
        }
    )
