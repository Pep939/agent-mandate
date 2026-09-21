"""Hypothesis property tests 1-6 (docs/test-plan.md §Property tests).

Run under Hypothesis default settings.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from mandate.domain.authority import (
    ActionToken,
    DelegationLink,
    RecordStatus,
    SpendCap,
)
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.decisions import Outcome
from mandate.domain.input import Counterparty, PolicyInput
from mandate.domain.state_machine import TRANSITIONS, transition_for
from mandate.policy.engine import evaluate
from tests.support.factories import make_claim, make_deal, make_input, make_proposal, make_record

D = DealState

ULID = st.integers(min_value=0, max_value=10**26 - 1).map(lambda n: f"{n:026d}")
TIMESTAMP = st.sampled_from(
    [
        "2025-12-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        "2026-01-15T12:00:00Z",
        "2026-06-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
    ]
)
TOKENS = list(ActionToken)
ANY_STATE = st.sampled_from(list(D))
ANY_EVENT = st.sampled_from(list(DealEvent))
MONEY = st.integers(min_value=0, max_value=3_000_000)


@st.composite
def policy_inputs(draw: st.DrawFn) -> PolicyInput:
    """Arbitrary well-typed PolicyInput, good or bad."""
    rec = make_record(
        counterparty_id=draw(st.one_of(st.none(), ULID)),
        allowed_actions=draw(st.lists(st.sampled_from(TOKENS), max_size=13)),
        prohibited_actions=draw(st.lists(st.sampled_from(TOKENS), max_size=13)),
        status=draw(st.sampled_from(list(RecordStatus))),
        not_before=draw(TIMESTAMP),
        expires_at=draw(TIMESTAMP),
        spend_cap=SpendCap(currency="USD", amount_minor=draw(MONEY)),
        max_negotiation_rounds=draw(st.integers(min_value=0, max_value=3)),
        disclosure_fields=draw(
            st.lists(st.sampled_from(["invoice_total", "customer_phone"]), max_size=2)
        ),
        requires_human_approval_for=draw(st.lists(st.sampled_from(TOKENS), max_size=2)),
    )
    deal = make_deal(
        state=draw(ANY_STATE),
        negotiated_rounds=draw(st.integers(min_value=0, max_value=5)),
        committed_minor=draw(MONEY),
        open_disputes=draw(st.integers(min_value=0, max_value=2)),
        open_approvals=draw(st.integers(min_value=0, max_value=2)),
    )
    return make_input(
        schema_version=draw(st.sampled_from(["0.1", "0.2", "legacy"])),
        now=draw(TIMESTAMP),
        record=rec,
        claim=make_claim(
            rec,
            signature_valid=draw(st.booleans()),
            delegation_chain=draw(
                st.lists(
                    st.builds(
                        DelegationLink,
                        parent_record_id=ULID,
                        scope_narrowing_valid=st.booleans(),
                    ),
                    max_size=2,
                )
            ),
        ),
        deal=deal,
        proposal=make_proposal(
            action=draw(
                st.one_of(st.sampled_from([t.value for t in TOKENS]), st.just("not_an_action"))
            ),
            amount_minor=draw(st.one_of(st.none(), MONEY)),
            currency=draw(st.sampled_from(["USD", "EUR"])),
            disclosure_fields=draw(
                st.lists(
                    st.sampled_from(["invoice_total", "customer_phone", "secret_note"]),
                    max_size=2,
                )
            ),
            deal_id=deal.deal_id,
        ),
        counterparty=Counterparty(id=draw(st.one_of(st.none(), ULID))),
    )


# ---------------------------------------------------------------------------
# Property 1: a prohibited action never evaluates to allow
# ---------------------------------------------------------------------------


@given(
    action=st.sampled_from(TOKENS),
    state=ANY_STATE,
    rounds=st.integers(min_value=0, max_value=12),
    committed=MONEY,
    amount=st.one_of(st.none(), MONEY),
    now=TIMESTAMP,
)
def test_prohibited_action_never_allowed(
    action: ActionToken,
    state: D,
    rounds: int,
    committed: int,
    amount: int | None,
    now: str,
):
    pi = make_input(
        now=now,
        record=make_record(
            prohibited_actions=[action],
            allowed_actions=list(ActionToken),
            spend_cap=SpendCap(currency="USD", amount_minor=10_000_000),
            max_negotiation_rounds=10,
        ),
        deal=make_deal(state, negotiated_rounds=rounds, committed_minor=committed),
        proposal=make_proposal(action=action.value, amount_minor=amount, currency="USD"),
    )
    assert evaluate(pi).outcome is not Outcome.ALLOW


# ---------------------------------------------------------------------------
# Property 2: a revoked or expired authority record never evaluates to allow
# ---------------------------------------------------------------------------


@given(
    kind=st.sampled_from(["revoked", "expired_status", "expired_time"]),
    action=st.sampled_from(TOKENS),
    state=ANY_STATE,
    now=TIMESTAMP,
)
def test_revoked_or_expired_never_allowed(kind: str, action: ActionToken, state: D, now: str):
    if kind == "revoked":
        rec = make_record(status=RecordStatus.REVOKED)
    elif kind == "expired_status":
        rec = make_record(status=RecordStatus.EXPIRED)
    else:
        # Strictly before every timestamp in TIMESTAMP, so `now` is always
        # past expiry. (now == expires_at is still valid: the engine treats
        # expires_at as inclusive.)
        rec = make_record(expires_at="2025-12-31T23:59:59Z")
    d = evaluate(
        make_input(
            now=now,
            record=rec,
            deal=make_deal(state),
            proposal=make_proposal(action=action.value),
        )
    )
    assert d.outcome is Outcome.DENY


# ---------------------------------------------------------------------------
# Property 3: monotonicity — increasing amount cannot flip deny into allow
#
# Steps 1-9 and 11-12 are amount-independent; step 10's total is monotonic
# non-decreasing in amount, and over-cap is needs_approval, never allow; the
# currency check is amount-independent. So a deny cannot become an allow.
# ---------------------------------------------------------------------------


@given(
    cap=MONEY,
    committed=MONEY,
    amount=MONEY,
    delta=st.integers(min_value=1, max_value=2_000_000),
)
def test_increasing_amount_cannot_flip_deny_to_allow(
    cap: int, committed: int, amount: int, delta: int
):
    def run(a: int) -> Outcome:
        return evaluate(
            make_input(
                record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=cap)),
                deal=make_deal(D.DRAFT, committed_minor=committed),
                proposal=make_proposal(action="request_quote", amount_minor=a, currency="USD"),
            )
        ).outcome

    if run(amount) is not Outcome.DENY:
        return
    assert run(amount + delta) is not Outcome.ALLOW


# ---------------------------------------------------------------------------
# Property 4: determinism — same input bytes, same decision bytes
# ---------------------------------------------------------------------------


@given(pi=policy_inputs())
def test_evaluate_is_byte_deterministic(pi: PolicyInput):
    assert evaluate(pi).model_dump_json() == evaluate(pi).model_dump_json()


# ---------------------------------------------------------------------------
# Property 5: deny by default, never raises
# ---------------------------------------------------------------------------


@given(pi=policy_inputs())
def test_evaluate_never_raises_and_outcome_is_well_formed(pi: PolicyInput):
    d = evaluate(pi)
    assert d.outcome in (Outcome.ALLOW, Outcome.DENY, Outcome.NEEDS_APPROVAL)


def _input_with(**overrides: Any) -> PolicyInput:
    deal = make_deal(D.QUOTE_RECEIVED)
    base: dict[str, Any] = {
        "deal": deal,
        "proposal": make_proposal(action="counteroffer", deal_id=deal.deal_id),
    }
    base.update(overrides)
    return make_input(**base)


DENY_MUTATIONS: dict[str, Callable[[], PolicyInput]] = {
    "bad_schema": lambda: _input_with().model_copy(update={"schema_version": "9.9"}),
    "bad_signature": lambda: _input_with(claim=make_claim(signature_valid=False)),
    "revoked": lambda: _input_with(record=make_record(status=RecordStatus.REVOKED)),
    "expired_time": lambda: _input_with(record=make_record(expires_at="2026-01-01T00:00:00Z")),
    "not_yet_valid": lambda: _input_with(record=make_record(not_before="2026-02-01T00:00:00Z")),
    "broken_delegation": lambda: _input_with(
        claim=make_claim(
            delegation_chain=[
                DelegationLink(parent_record_id="0" * 26, scope_narrowing_valid=False)
            ]
        )
    ),
    "audience_mismatch": lambda: _input_with(
        record=make_record(counterparty_id="1" * 26),
        counterparty=Counterparty(id="2" * 26),
    ),
    "prohibited_action": lambda: _input_with(
        record=make_record(prohibited_actions=[ActionToken.COUNTEROFFER])
    ),
    "unknown_action": lambda: _input_with(proposal=make_proposal(action="teleport")),
    "action_not_allowed": lambda: _input_with(
        record=make_record(allowed_actions=[ActionToken.REQUEST_QUOTE])
    ),
    "invalid_state": lambda: _input_with(deal=make_deal(D.CAPTURED)),
    "bad_disclosure": lambda: _input_with(
        proposal=make_proposal(action="counteroffer", disclosure_fields=["customer_phone"])
    ),
    "currency_mismatch": lambda: _input_with(
        proposal=make_proposal(action="counteroffer", amount_minor=1, currency="EUR")
    ),
    "negotiation_limit": lambda: _input_with(
        deal=make_deal(D.QUOTE_RECEIVED, negotiated_rounds=10)
    ),
}


@given(name=st.sampled_from(sorted(DENY_MUTATIONS)))
def test_deny_by_default_under_any_single_break(name: str):
    assert evaluate(DENY_MUTATIONS[name]()).outcome is Outcome.DENY


# ---------------------------------------------------------------------------
# Property 6: transition determinism; unknown pairs always deny
# ---------------------------------------------------------------------------


@given(state=ANY_STATE, event=ANY_EVENT)
def test_transition_is_deterministic_and_unknown_pairs_deny(state: D, event: DealEvent):
    r1 = transition_for(state, event)
    r2 = transition_for(state, event)
    assert r1 == r2
    if r1 is None:
        assert (state, event) not in TRANSITIONS
    else:
        assert TRANSITIONS[(state, event)] == r1
