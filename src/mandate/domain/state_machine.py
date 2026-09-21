"""Explicit transition table and action-to-state mapping.

The state machine is a data table, not ad-hoc if/else logic (CLAUDE.md).
Every (state, event) pair is either in TRANSITIONS or denied.
"""

from __future__ import annotations

from mandate.domain.authority import ActionToken
from mandate.domain.deals import Deal, DealEvent, DealState, apply_event

TRANSITIONS: dict[tuple[DealState, DealEvent], DealState] = {
    # Row 1
    (DealState.DRAFT, DealEvent.QUOTE_REQUESTED): DealState.QUOTE_REQUESTED,
    # Row 2
    (DealState.QUOTE_REQUESTED, DealEvent.QUOTE_RECEIVED): DealState.QUOTE_RECEIVED,
    # Row 3 (two source states)
    (DealState.QUOTE_RECEIVED, DealEvent.COUNTEROFFERED): DealState.NEGOTIATING,
    (DealState.NEGOTIATING, DealEvent.COUNTEROFFERED): DealState.NEGOTIATING,
    # Row 4 (two source states)
    (DealState.QUOTE_RECEIVED, DealEvent.AGREEMENT_REACHED): DealState.AGREED,
    (DealState.NEGOTIATING, DealEvent.AGREEMENT_REACHED): DealState.AGREED,
    # Row 5
    (DealState.AGREED, DealEvent.WORK_STARTED): DealState.IN_PROGRESS,
    # Row 6
    (DealState.IN_PROGRESS, DealEvent.CHANGE_REQUESTED): DealState.CHANGE_REQUESTED,
    # Row 7
    (DealState.CHANGE_REQUESTED, DealEvent.CHANGE_APPROVED): DealState.IN_PROGRESS,
    # Row 8
    (DealState.CHANGE_REQUESTED, DealEvent.CHANGE_REJECTED): DealState.IN_PROGRESS,
    # Row 9
    (DealState.IN_PROGRESS, DealEvent.COMPLETION_CLAIMED): DealState.COMPLETED,
    # Row 10
    (DealState.COMPLETED, DealEvent.ACCEPTANCE_WINDOW_OPENED): DealState.ACCEPTANCE_WINDOW,
    # Row 11
    (DealState.ACCEPTANCE_WINDOW, DealEvent.ACCEPTED): DealState.ACCEPTED,
    # Row 12
    (DealState.ACCEPTANCE_WINDOW, DealEvent.DISPUTE_OPENED): DealState.DISPUTED,
    # Row 13
    (DealState.DISPUTED, DealEvent.ACCEPTED): DealState.ACCEPTED,
    # Row 14
    (DealState.DISPUTED, DealEvent.REFUNDED): DealState.REFUNDED,
    # Row 15
    (DealState.DISPUTED, DealEvent.PARTIALLY_REFUNDED): DealState.PARTIALLY_REFUNDED,
    # Row 16
    (DealState.ACCEPTED, DealEvent.PAYMENT_INITIATED): DealState.PAYMENT_PENDING,
    # Row 17
    (DealState.PAYMENT_PENDING, DealEvent.PAYMENT_CONFIRMED): DealState.CAPTURED,
    # Row 18
    (DealState.PAYMENT_PENDING, DealEvent.PAYMENT_FAILED): DealState.FAILED,
    # Row 19
    (DealState.FAILED, DealEvent.RESUMED): DealState.PAYMENT_PENDING,
    # Row 20 (five source states, A5 includes AGREED)
    (DealState.DRAFT, DealEvent.EXPIRED): DealState.EXPIRED,
    (DealState.QUOTE_REQUESTED, DealEvent.EXPIRED): DealState.EXPIRED,
    (DealState.QUOTE_RECEIVED, DealEvent.EXPIRED): DealState.EXPIRED,
    (DealState.NEGOTIATING, DealEvent.EXPIRED): DealState.EXPIRED,
    (DealState.AGREED, DealEvent.EXPIRED): DealState.EXPIRED,
    # Row 21 (A4: all states except CAPTURED, PARTIALLY_REFUNDED, REFUNDED,
    # CANCELLED, EXPIRED, FAILED)
    (DealState.DRAFT, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.QUOTE_REQUESTED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.QUOTE_RECEIVED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.NEGOTIATING, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.AGREED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.IN_PROGRESS, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.CHANGE_REQUESTED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.COMPLETED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.ACCEPTANCE_WINDOW, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.DISPUTED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.ACCEPTED, DealEvent.CANCELLED): DealState.CANCELLED,
    (DealState.PAYMENT_PENDING, DealEvent.CANCELLED): DealState.CANCELLED,
}

TERMINAL_STATES: frozenset[DealState] = frozenset(
    {
        DealState.CAPTURED,
        DealState.PARTIALLY_REFUNDED,
        DealState.REFUNDED,
        DealState.CANCELLED,
        DealState.EXPIRED,
    }
)

CANCEL_EXCLUDED: frozenset[DealState] = TERMINAL_STATES | frozenset({DealState.FAILED})

ACTION_VALID_STATES: dict[ActionToken, frozenset[DealState]] = {
    ActionToken.REQUEST_QUOTE: frozenset({DealState.DRAFT}),
    ActionToken.COUNTEROFFER: frozenset({DealState.QUOTE_RECEIVED, DealState.NEGOTIATING}),
    ActionToken.ACCEPT_AGREEMENT: frozenset({DealState.QUOTE_RECEIVED, DealState.NEGOTIATING}),
    ActionToken.START_WORK: frozenset({DealState.AGREED}),
    ActionToken.PROPOSE_CHANGE: frozenset({DealState.IN_PROGRESS}),
    ActionToken.APPROVE_CHANGE_ORDER: frozenset({DealState.CHANGE_REQUESTED}),
    ActionToken.CLAIM_COMPLETION: frozenset({DealState.IN_PROGRESS}),
    ActionToken.ACCEPT_COMPLETION: frozenset({DealState.ACCEPTANCE_WINDOW, DealState.DISPUTED}),
    ActionToken.OPEN_DISPUTE: frozenset({DealState.ACCEPTANCE_WINDOW}),
    ActionToken.INITIATE_PAYMENT: frozenset({DealState.ACCEPTED}),
    ActionToken.CAPTURE_PAYMENT: frozenset({DealState.PAYMENT_PENDING}),
    ActionToken.CANCEL_DEAL: frozenset(s for s in DealState if s not in CANCEL_EXCLUDED),
    ActionToken.RESOLVE_DISPUTE: frozenset({DealState.DISPUTED}),
}

ACTION_EVENTS: dict[ActionToken, DealEvent | None] = {
    # ADR-0009: the only action→event mapping. RESOLVE_DISPUTE is
    # decision-only — its resolution outcomes are separate events
    # (accepted / refunded), and the dispute counter decrements in
    # apply_action instead.
    ActionToken.REQUEST_QUOTE: DealEvent.QUOTE_REQUESTED,
    ActionToken.COUNTEROFFER: DealEvent.COUNTEROFFERED,
    ActionToken.ACCEPT_AGREEMENT: DealEvent.AGREEMENT_REACHED,
    ActionToken.START_WORK: DealEvent.WORK_STARTED,
    ActionToken.PROPOSE_CHANGE: DealEvent.CHANGE_REQUESTED,
    ActionToken.APPROVE_CHANGE_ORDER: DealEvent.CHANGE_APPROVED,
    ActionToken.CLAIM_COMPLETION: DealEvent.COMPLETION_CLAIMED,
    ActionToken.ACCEPT_COMPLETION: DealEvent.ACCEPTED,
    ActionToken.OPEN_DISPUTE: DealEvent.DISPUTE_OPENED,
    ActionToken.INITIATE_PAYMENT: DealEvent.PAYMENT_INITIATED,
    ActionToken.CAPTURE_PAYMENT: DealEvent.PAYMENT_CONFIRMED,
    ActionToken.CANCEL_DEAL: DealEvent.CANCELLED,
    ActionToken.RESOLVE_DISPUTE: None,
}

NEGOTIATION_ACTIONS: frozenset[ActionToken] = frozenset({ActionToken.COUNTEROFFER})

PAYMENT_ACTIONS: frozenset[ActionToken] = frozenset(
    {ActionToken.INITIATE_PAYMENT, ActionToken.CAPTURE_PAYMENT}
)


def transition_for(state: DealState, event: DealEvent) -> DealState | None:
    """Return the target state, or None if the pair is not in the table."""
    return TRANSITIONS.get((state, event))


def terminal_states() -> frozenset[DealState]:
    """States with no outgoing transitions (FAILED excluded — it has `resumed`)."""
    return TERMINAL_STATES


def apply_action(deal: Deal, action: ActionToken, amount_minor: int | None = None) -> Deal:
    """The deal after an ALLOWed action (ADR-0009).

    Resolves the action's event, computes the target state from the table and
    applies the counter rules. Raises ValueError if the (state, event) pair is
    not in TRANSITIONS — callers recheck against stored state first.

    One action-level rule beyond the event table: RESOLVE_DISPUTE makes no
    state change but closes a dispute (open_disputes -= 1, floor 0), without
    which a resolved dispute would block payment forever (engine step 8).
    """
    event = ACTION_EVENTS[action]
    new = deal
    if event is not None:
        target = transition_for(deal.state, event)
        if target is None:
            msg = f"no transition from {deal.state.value} on {event.value}"
            raise ValueError(msg)
        new = apply_event(deal, event, target, amount_minor)
    if action is ActionToken.RESOLVE_DISPUTE:
        new = new.model_copy(update={"open_disputes": max(0, new.open_disputes - 1)})
    return new
