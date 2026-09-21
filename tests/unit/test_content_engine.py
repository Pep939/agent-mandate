"""Engine steps 9b and 12b — the content screen (ADR-0016).

Step 9b denies a near-certain undeclared disclosure; step 12b holds for a
person on a probable one, on probable hostility, or when the screen was
unavailable. Both may only *narrow*: no claim, however clean, can turn a
deny or a hold into an allow. The Hypothesis proof of that property lives in
`tests/property/test_content_monotonicity.py`; these are the named cases.
"""

from __future__ import annotations

from mandate.domain.authority import ActionToken, SpendCap
from mandate.domain.deals import DealState
from mandate.domain.decisions import Outcome, PolicyDecision, ReasonCode
from mandate.policy.engine import CONTENT_DENY_BP, CONTENT_HOLD_BP, evaluate
from tests.support.factories import make_claims

D = DealState


def _assert_decision(d: PolicyDecision, outcome: Outcome, reason: ReasonCode) -> PolicyDecision:
    assert d.outcome is outcome
    assert d.reason_code is reason
    return d


class TestStep09bDisclosureDetected:
    def test_near_certain_undeclared_field_denies(self, make_input):
        d = evaluate(make_input(content=make_claims({"customer_phone": CONTENT_DENY_BP})))
        _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_DETECTED)
        assert d.matched_rule == "step_09b_content_disclosure"
        assert "customer_phone" in d.explanation

    def test_allowlisted_field_is_not_a_leak(self, make_input, make_record):
        d = evaluate(
            make_input(
                record=make_record(disclosure_fields=["invoice_total"]),
                content=make_claims({"invoice_total": 10_000}),
            )
        )
        assert d.outcome is Outcome.ALLOW

    def test_one_leak_among_allowed_fields_still_denies(self, make_input, make_record):
        d = evaluate(
            make_input(
                record=make_record(disclosure_fields=["invoice_total"]),
                content=make_claims({"invoice_total": 10_000, "customer_phone": 9_800}),
            )
        )
        _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_DETECTED)

    def test_deny_beats_the_spend_cap_hold(self, make_input, make_record, make_proposal):
        """Step 9b precedes step 10, and an earlier deny always wins
        (invariant 6): the message never goes out to ask about the money."""
        d = evaluate(
            make_input(
                record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=0)),
                proposal=make_proposal(amount_minor=1),
                content=make_claims({"customer_phone": 9_900}),
            )
        )
        _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_DETECTED)

    def test_just_below_the_deny_threshold_holds_instead(self, make_input):
        d = evaluate(make_input(content=make_claims({"customer_phone": CONTENT_DENY_BP - 1})))
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.CONTENT_REVIEW_REQUIRED)

    def test_an_earlier_step_still_denies_first(self, make_input, make_record):
        """A revoked mandate is answered at step 3 — the screen never runs
        the deal past an authority failure."""
        d = evaluate(
            make_input(
                record=make_record(status="revoked"),
                content=make_claims({"customer_phone": 10_000}),
            )
        )
        _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_REVOKED)


class TestStep12bHolds:
    def test_probable_leak_holds_for_a_person(self, make_input):
        d = evaluate(make_input(content=make_claims({"customer_phone": CONTENT_HOLD_BP})))
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.CONTENT_REVIEW_REQUIRED)
        assert d.matched_rule == "step_12b_content_hold"

    def test_below_the_hold_threshold_allows(self, make_input):
        d = evaluate(make_input(content=make_claims({"customer_phone": CONTENT_HOLD_BP - 1})))
        assert d.outcome is Outcome.ALLOW

    def test_hostile_content_holds(self, make_input):
        d = evaluate(make_input(content=make_claims(hostility_bp=9_700)))
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.HOSTILE_CONTENT_SUSPECTED)

    def test_unavailable_screen_holds_and_never_allows(self, make_input):
        """Fail toward caution: an outage is 'a person must look', not
        'nothing was found' and not 'the deal is dead'."""
        d = evaluate(make_input(content=make_claims(available=False)))
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.CONTENT_SCREEN_UNAVAILABLE)

    def test_unavailable_screen_does_not_mask_an_earlier_deny(self, make_input, make_deal):
        d = evaluate(make_input(deal=make_deal(D.CAPTURED), content=make_claims(available=False)))
        _assert_decision(d, Outcome.DENY, ReasonCode.INVALID_TRANSITION)

    def test_leak_hold_is_reported_before_hostility(self, make_input):
        """Both fire: the disclosure reason is the more actionable one."""
        d = evaluate(make_input(content=make_claims({"customer_phone": 8_000}, hostility_bp=9_000)))
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.CONTENT_REVIEW_REQUIRED)

    def test_persuasion_and_urgency_are_advisory_only(self, make_input):
        """They order the operator's queue and colour the badge; they never
        move a decision (ADR-0016)."""
        d = evaluate(make_input(content=make_claims(persuasion_bp=10_000, urgency_level=3)))
        assert d.outcome is Outcome.ALLOW


class TestNarrowingOnly:
    def test_clean_content_leaves_an_allow_alone(self, make_input):
        assert evaluate(make_input(content=make_claims())).outcome is Outcome.ALLOW

    def test_no_content_is_the_old_behaviour(self, make_input):
        assert evaluate(make_input()).outcome is Outcome.ALLOW

    def test_clean_screen_cannot_rescue_a_denied_proposal(self, make_input, make_record):
        d = evaluate(
            make_input(
                record=make_record(prohibited_actions=[ActionToken.REQUEST_QUOTE]),
                content=make_claims(),
            )
        )
        _assert_decision(d, Outcome.DENY, ReasonCode.ACTION_PROHIBITED)

    def test_clean_screen_cannot_lift_an_approval_requirement(self, make_input, make_record):
        d = evaluate(
            make_input(
                record=make_record(requires_human_approval_for=[ActionToken.REQUEST_QUOTE]),
                content=make_claims(),
            )
        )
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.APPROVAL_REQUIRED)

    def test_clean_screen_cannot_lift_an_over_cap_hold(
        self, make_input, make_record, make_proposal
    ):
        d = evaluate(
            make_input(
                record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=0)),
                proposal=make_proposal(amount_minor=1),
                content=make_claims(),
            )
        )
        _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.SPEND_CAP_EXCEEDED)

    def test_engine_stays_byte_deterministic_with_content(self, make_input):
        pi = make_input(content=make_claims({"customer_phone": 7_500}, hostility_bp=100))
        assert evaluate(pi).model_dump_json() == evaluate(pi).model_dump_json()

    def test_content_reason_codes_never_accompany_an_allow(self, make_input):
        content_codes = {
            ReasonCode.DISCLOSURE_DETECTED,
            ReasonCode.CONTENT_REVIEW_REQUIRED,
            ReasonCode.HOSTILE_CONTENT_SUSPECTED,
            ReasonCode.CONTENT_SCREEN_UNAVAILABLE,
        }
        for claims in (
            make_claims(),
            make_claims({"customer_phone": 9_900}),
            make_claims({"customer_phone": 7_100}),
            make_claims(hostility_bp=9_900),
            make_claims(available=False),
        ):
            d = evaluate(make_input(content=claims))
            if d.reason_code in content_codes:
                assert d.outcome is not Outcome.ALLOW
