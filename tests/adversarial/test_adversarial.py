"""Adversarial fixture set (docs/test-plan.md §Adversarial fixtures).

A "sloppy/malicious agent" as proposal inputs only — no live agent yet
(live-agent misbehavior scenarios are Phases 3-5).
"""

from __future__ import annotations

import pytest

from mandate.domain.authority import SpendCap
from mandate.domain.deals import DealState
from mandate.domain.decisions import Outcome, ReasonCode
from mandate.domain.input import Counterparty
from mandate.policy.engine import evaluate
from tests.support.factories import new_ulid

D = DealState


def test_expired_mandate_reused_after_expiry(make_record, make_input):
    rec = make_record(expires_at="2026-01-01T00:00:00Z")
    d = evaluate(make_input(record=rec, now="2026-06-01T00:00:00Z"))
    _deny(d, ReasonCode.RECORD_EXPIRED)


def test_disclosure_field_outside_allow_list_denied(make_record, make_input, make_proposal):
    rec = make_record(disclosure_fields=["invoice_total"])
    d = evaluate(
        make_input(record=rec, proposal=make_proposal(disclosure_fields=["customer_phone"]))
    )
    _deny(d, ReasonCode.DISCLOSURE_NOT_ALLOWED)


def test_spend_cap_bypass_via_small_increments_needs_approval(
    make_record, make_deal, make_input, make_proposal
):
    # Nine 100_001-minor change orders fit under a 1_000_000 cap; the tenth
    # crosses it. Cumulative exposure (invariant 8) must not be bypassable by
    # splitting one large ask into small ones.
    rec = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1_000_000))
    committed = 0
    outcomes: list[Outcome] = []
    for _ in range(11):
        deal = make_deal(D.CHANGE_REQUESTED, committed_minor=committed)
        d = evaluate(
            make_input(
                record=rec,
                deal=deal,
                proposal=make_proposal(
                    action="approve_change_order",
                    deal_id=deal.deal_id,
                    amount_minor=100_001,
                    currency="USD",
                ),
            )
        )
        outcomes.append(d.outcome)
        if d.outcome is Outcome.ALLOW:
            committed += 100_001
    assert outcomes[:9] == [Outcome.ALLOW] * 9
    assert all(o is Outcome.NEEDS_APPROVAL for o in outcomes[9:])


@pytest.mark.parametrize("rounds", [10, 11], ids=["at_cap", "past_cap"])
def test_negotiation_round_exhaustion_denied(make_deal, make_input, make_proposal, rounds: int):
    deal = make_deal(D.NEGOTIATING, negotiated_rounds=rounds)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="counteroffer", deal_id=deal.deal_id),
        )
    )
    _deny(d, ReasonCode.NEGOTIATION_LIMIT_REACHED)


def test_replay_shaped_duplicate_is_stateless_and_deterministic(make_input):
    # The engine is stateless: a byte-identical replayed proposal evaluates
    # identically. Replay *detection* (seen-request store on nonce,
    # request_id, idempotency_key) is owned by the boundary per
    # specs/policy-schema.md §Anti-replay; replay_detected is a boundary
    # reason code, not one evaluate() produces.
    pi = make_input()
    d1 = evaluate(pi)
    d2 = evaluate(pi.model_copy(deep=True))
    assert d1 == d2
    assert d1.reason_code is not ReasonCode.REPLAY_DETECTED


def test_payment_initiated_while_dispute_open_denied(make_deal, make_input, make_proposal):
    deal = make_deal(D.ACCEPTED, open_disputes=1)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="initiate_payment", deal_id=deal.deal_id),
        )
    )
    _deny(d, ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE)


def test_payment_initiated_with_open_required_approval_denied(make_deal, make_input, make_proposal):
    deal = make_deal(D.ACCEPTED, open_approvals=1)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="initiate_payment", deal_id=deal.deal_id),
        )
    )
    _deny(d, ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL)


def test_counterparty_mismatch_on_audience_restricted_record(
    make_record,
    make_input,
):
    rec = make_record(counterparty_id=new_ulid())
    d = evaluate(make_input(record=rec, counterparty=Counterparty(id=new_ulid())))
    _deny(d, ReasonCode.AUDIENCE_MISMATCH)


def test_schema_version_mismatch_denied_both_directions(make_input):
    downgrade = evaluate(make_input(schema_version="0.0"))
    _deny(downgrade, ReasonCode.UNKNOWN_SCHEMA_VERSION)
    upgrade = evaluate(make_input(schema_version="9.9"))
    _deny(upgrade, ReasonCode.UNKNOWN_SCHEMA_VERSION)


def _deny(d, reason: ReasonCode) -> None:
    assert d.outcome is Outcome.DENY, f"expected deny, got {d.outcome} ({d.reason_code})"
    assert d.reason_code is reason
