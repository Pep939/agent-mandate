"""Unit tests for ACTION_EVENTS and the counter rules (ADR-0009).

The pin test is load-bearing: every (action, valid state) pair must resolve
to a real transition — the mapping can never drift from the table silently.
"""

from __future__ import annotations

import pytest

from mandate.domain.authority import ActionToken
from mandate.domain.deals import DealEvent, DealState, apply_event
from mandate.domain.state_machine import (
    ACTION_EVENTS,
    ACTION_VALID_STATES,
    apply_action,
    transition_for,
)
from tests.support.factories import make_deal


class TestActionEventsPin:
    @pytest.mark.parametrize("action", list(ActionToken), ids=lambda a: a.value)
    def test_every_action_has_a_table_entry(self, action):
        assert action in ACTION_EVENTS

    @pytest.mark.parametrize("action", list(ActionToken), ids=lambda a: a.value)
    @pytest.mark.parametrize("state", list(DealState), ids=lambda s: s.value)
    def test_mapping_is_consistent_with_the_transition_table(self, action, state):
        event = ACTION_EVENTS[action]
        if state not in ACTION_VALID_STATES[action]:
            return  # engine step 8 denies these; the store never sees them
        if event is None:
            # decision-only action (resolve_dispute)
            return
        assert transition_for(state, event) is not None, (
            f"{action.value} from {state.value} maps to {event.value}, not in TRANSITIONS"
        )


class TestApplyActionCounters:
    def test_counteroffer_increments_rounds(self):
        deal = make_deal(state=DealState.NEGOTIATING)
        new = apply_action(deal, ActionToken.COUNTEROFFER)
        assert new.state is DealState.NEGOTIATING
        assert new.negotiated_rounds == deal.negotiated_rounds + 1

    def test_agreement_reached_commits_amount(self):
        deal = make_deal(state=DealState.NEGOTIATING)
        new = apply_action(deal, ActionToken.ACCEPT_AGREEMENT, amount_minor=50_000)
        assert new.state is DealState.AGREED
        assert new.committed_minor == 50_000

    def test_change_approved_adds_to_committed(self):
        deal = make_deal(state=DealState.CHANGE_REQUESTED, committed_minor=50_000)
        new = apply_action(deal, ActionToken.APPROVE_CHANGE_ORDER, amount_minor=12_000)
        assert new.state is DealState.IN_PROGRESS
        assert new.committed_minor == 62_000

    def test_amount_none_defaults_to_zero(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        new = apply_action(deal, ActionToken.ACCEPT_AGREEMENT)
        assert new.committed_minor == 0

    def test_dispute_opened_increments_disputes(self):
        deal = make_deal(state=DealState.ACCEPTANCE_WINDOW)
        new = apply_action(deal, ActionToken.OPEN_DISPUTE)
        assert new.state is DealState.DISPUTED
        assert new.open_disputes == 1

    def test_accepted_from_disputed_decrements_disputes(self):
        deal = make_deal(state=DealState.DISPUTED, open_disputes=1)
        new = apply_action(deal, ActionToken.ACCEPT_COMPLETION)
        assert new.state is DealState.ACCEPTED
        assert new.open_disputes == 0

    def test_accepted_from_acceptance_window_keeps_disputes(self):
        deal = make_deal(state=DealState.ACCEPTANCE_WINDOW)
        new = apply_action(deal, ActionToken.ACCEPT_COMPLETION)
        assert new.open_disputes == 0

    def test_resolve_dispute_decrements_without_state_change(self):
        deal = make_deal(state=DealState.DISPUTED, open_disputes=1)
        new = apply_action(deal, ActionToken.RESOLVE_DISPUTE)
        assert new.state is DealState.DISPUTED
        assert new.open_disputes == 0

    def test_resolve_dispute_floors_at_zero(self):
        deal = make_deal(state=DealState.DISPUTED, open_disputes=0)
        new = apply_action(deal, ActionToken.RESOLVE_DISPUTE)
        assert new.open_disputes == 0

    def test_cancel_makes_no_counter_changes(self):
        deal = make_deal(state=DealState.IN_PROGRESS, negotiated_rounds=3, committed_minor=9)
        new = apply_action(deal, ActionToken.CANCEL_DEAL)
        assert new.state is DealState.CANCELLED
        assert new.negotiated_rounds == 3
        assert new.committed_minor == 9


class TestApplyActionErrors:
    def test_invalid_transition_raises(self):
        deal = make_deal(state=DealState.CAPTURED)
        with pytest.raises(ValueError, match="no transition"):
            apply_action(deal, ActionToken.REQUEST_QUOTE)


class TestApplyEventRefundRules:
    def test_refunded_zeroes_disputes(self):
        deal = make_deal(state=DealState.DISPUTED, open_disputes=2)
        new = apply_event(deal, DealEvent.REFUNDED, DealState.REFUNDED)
        assert new.state is DealState.REFUNDED
        assert new.open_disputes == 0

    def test_partially_refunded_zeroes_disputes(self):
        deal = make_deal(state=DealState.DISPUTED, open_disputes=1)
        new = apply_event(deal, DealEvent.PARTIALLY_REFUNDED, DealState.PARTIALLY_REFUNDED)
        assert new.open_disputes == 0

    def test_payment_events_make_no_counter_changes(self):
        deal = make_deal(state=DealState.ACCEPTED, committed_minor=1000)
        new = apply_event(deal, DealEvent.PAYMENT_INITIATED, DealState.PAYMENT_PENDING)
        assert new.state is DealState.PAYMENT_PENDING
        assert new.committed_minor == 1000
        assert new.open_disputes == 0
