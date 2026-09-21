"""Transition-table tests (docs/test-plan.md §Unit tests).

The expected table below is copied from specs/state-machine.md rows 1-21,
NOT from state_machine.py, so this file pins spec and code to each other:
every spec row resolves, every unlisted (state, event) pair denies, and
terminal states admit nothing.
"""

from __future__ import annotations

import pytest

from mandate.domain.authority import ActionToken
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.state_machine import (
    ACTION_VALID_STATES,
    NEGOTIATION_ACTIONS,
    PAYMENT_ACTIONS,
    TERMINAL_STATES,
    TRANSITIONS,
    transition_for,
)

A = ActionToken
D = DealState
E = DealEvent

# (from, event, to, guard) — spec rows 1-20, copied verbatim.
_ROWS: list[tuple[DealState, DealEvent, DealState, ActionToken | None]] = [
    (D.DRAFT, E.QUOTE_REQUESTED, D.QUOTE_REQUESTED, A.REQUEST_QUOTE),
    (D.QUOTE_REQUESTED, E.QUOTE_RECEIVED, D.QUOTE_RECEIVED, None),
    (D.QUOTE_RECEIVED, E.COUNTEROFFERED, D.NEGOTIATING, A.COUNTEROFFER),
    (D.NEGOTIATING, E.COUNTEROFFERED, D.NEGOTIATING, A.COUNTEROFFER),
    (D.QUOTE_RECEIVED, E.AGREEMENT_REACHED, D.AGREED, A.ACCEPT_AGREEMENT),
    (D.NEGOTIATING, E.AGREEMENT_REACHED, D.AGREED, A.ACCEPT_AGREEMENT),
    (D.AGREED, E.WORK_STARTED, D.IN_PROGRESS, A.START_WORK),
    (D.IN_PROGRESS, E.CHANGE_REQUESTED, D.CHANGE_REQUESTED, A.PROPOSE_CHANGE),
    (D.CHANGE_REQUESTED, E.CHANGE_APPROVED, D.IN_PROGRESS, A.APPROVE_CHANGE_ORDER),
    (D.CHANGE_REQUESTED, E.CHANGE_REJECTED, D.IN_PROGRESS, None),
    (D.IN_PROGRESS, E.COMPLETION_CLAIMED, D.COMPLETED, A.CLAIM_COMPLETION),
    (D.COMPLETED, E.ACCEPTANCE_WINDOW_OPENED, D.ACCEPTANCE_WINDOW, None),
    (D.ACCEPTANCE_WINDOW, E.ACCEPTED, D.ACCEPTED, A.ACCEPT_COMPLETION),
    (D.ACCEPTANCE_WINDOW, E.DISPUTE_OPENED, D.DISPUTED, A.OPEN_DISPUTE),
    (D.DISPUTED, E.ACCEPTED, D.ACCEPTED, A.ACCEPT_COMPLETION),
    (D.DISPUTED, E.REFUNDED, D.REFUNDED, A.RESOLVE_DISPUTE),
    (D.DISPUTED, E.PARTIALLY_REFUNDED, D.PARTIALLY_REFUNDED, A.RESOLVE_DISPUTE),
    (D.ACCEPTED, E.PAYMENT_INITIATED, D.PAYMENT_PENDING, A.INITIATE_PAYMENT),
    (D.PAYMENT_PENDING, E.PAYMENT_CONFIRMED, D.CAPTURED, None),
    (D.PAYMENT_PENDING, E.PAYMENT_FAILED, D.FAILED, None),
    (D.FAILED, E.RESUMED, D.PAYMENT_PENDING, None),
    (D.DRAFT, E.EXPIRED, D.EXPIRED, None),
    (D.QUOTE_REQUESTED, E.EXPIRED, D.EXPIRED, None),
    (D.QUOTE_RECEIVED, E.EXPIRED, D.EXPIRED, None),
    (D.NEGOTIATING, E.EXPIRED, D.EXPIRED, None),
    (D.AGREED, E.EXPIRED, D.EXPIRED, None),
]
# Row 21 (A4): cancel_deal from every state except CAPTURED,
# PARTIALLY_REFUNDED, REFUNDED, CANCELLED, EXPIRED, FAILED.
_CANCEL_EXCLUDED = {D.CAPTURED, D.PARTIALLY_REFUNDED, D.REFUNDED, D.CANCELLED, D.EXPIRED, D.FAILED}
_ROWS.extend(
    (s, E.CANCELLED, D.CANCELLED, A.CANCEL_DEAL) for s in DealState if s not in _CANCEL_EXCLUDED
)

SPEC_ROWS: tuple[tuple[DealState, DealEvent, DealState, ActionToken | None], ...] = tuple(_ROWS)

EXPECTED_TRANSITIONS: dict[tuple[DealState, DealEvent], DealState] = {
    (src, event): target for src, event, target, _guard in SPEC_ROWS
}

ALL_PAIRS: list[tuple[DealState, DealEvent]] = [(s, e) for s in DealState for e in DealEvent]
INVALID_PAIRS: list[tuple[DealState, DealEvent]] = [
    pair for pair in ALL_PAIRS if pair not in TRANSITIONS
]


def _expected_action_states() -> dict[ActionToken, frozenset[DealState]]:
    return {
        action: frozenset(src for src, _event, _target, guard in SPEC_ROWS if guard is action)
        for action in ActionToken
    }


EXPECTED_ACTION_STATES = _expected_action_states()


def test_table_matches_spec_row_for_row():
    assert TRANSITIONS == EXPECTED_TRANSITIONS


def test_table_has_exactly_38_pairs():
    assert len(TRANSITIONS) == 38


def test_pair_space_is_18_states_times_20_events():
    assert len(ALL_PAIRS) == len(DealState) * len(DealEvent) == 360


def test_exactly_322_pairs_are_invalid():
    assert len(INVALID_PAIRS) == 322


@pytest.mark.parametrize(
    ("state", "event", "target"),
    [(src, event, target) for src, event, target, _guard in SPEC_ROWS],
    ids=[f"{src.value}--{event.value}" for src, event, _target, _guard in SPEC_ROWS],
)
def test_every_spec_row_resolves(state: DealState, event: DealEvent, target: DealState):
    assert transition_for(state, event) is target


@pytest.mark.parametrize(
    ("state", "event"),
    INVALID_PAIRS,
    ids=[f"{s.value}--{e.value}" for s, e in INVALID_PAIRS],
)
def test_unlisted_pair_denies(state: DealState, event: DealEvent):
    assert transition_for(state, event) is None


def test_terminal_states_match_spec():
    assert (
        frozenset({D.CAPTURED, D.PARTIALLY_REFUNDED, D.REFUNDED, D.CANCELLED, D.EXPIRED})
        == TERMINAL_STATES
    )


def test_terminal_states_admit_nothing():
    for state in TERMINAL_STATES:
        for event in DealEvent:
            assert transition_for(state, event) is None


def test_every_non_terminal_state_has_an_outgoing_transition():
    for state in DealState:
        if state in TERMINAL_STATES:
            continue
        assert any(transition_for(state, event) is not None for event in DealEvent)


def test_failed_is_retryable_not_terminal():
    # Spec: FAILED is terminal *except* it has `resumed` back to PAYMENT_PENDING.
    assert D.FAILED not in TERMINAL_STATES
    assert transition_for(D.FAILED, E.RESUMED) is D.PAYMENT_PENDING


def test_action_valid_states_match_spec_guards():
    # 12 of the 13 tokens guard at least one spec row; each maps to exactly
    # the source states of its rows.
    for action in ActionToken:
        if action is A.CAPTURE_PAYMENT:
            continue
        assert ACTION_VALID_STATES[action] == EXPECTED_ACTION_STATES[action]


def test_capture_payment_valid_states():
    # No spec row is guarded by capture_payment (row 17 is guarded by the
    # provider confirmation), so this pins the code's own mapping: capture is
    # only proposed from PAYMENT_PENDING.
    assert ACTION_VALID_STATES[A.CAPTURE_PAYMENT] == frozenset({D.PAYMENT_PENDING})


def test_action_map_covers_all_tokens():
    assert set(ACTION_VALID_STATES) == set(ActionToken)


def test_every_action_maps_to_at_least_one_state():
    assert all(len(states) > 0 for states in ACTION_VALID_STATES.values())


def test_negotiation_action_set():
    assert frozenset({A.COUNTEROFFER}) == NEGOTIATION_ACTIONS


def test_payment_action_set():
    assert frozenset({A.INITIATE_PAYMENT, A.CAPTURE_PAYMENT}) == PAYMENT_ACTIONS
