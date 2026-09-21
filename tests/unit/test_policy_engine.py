"""Policy engine tests (docs/test-plan.md §Unit tests).

One named test per evaluation-order step (specs/policy-schema.md §Evaluation
order), every engine-reachable reason_code, precedence, spend, disclosure,
approval shape, and idempotency shape.

Approval semantics note: `PolicyInput` carries no recorded-approval field, so
the engine never assumes approval — any action in
`requires_human_approval_for` is `needs_approval`. The approve → allow flow
(approval events bound to (deal_id, idempotency_key, action, amount_minor),
single-use) lives in the ledger/boundary (Phases 3+); one-time overrides are
their own signed record (ADR-0004 A2).
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from mandate.domain.authority import (
    ActionToken,
    DelegationLink,
    RecordStatus,
    SpendCap,
)
from mandate.domain.deals import DealState
from mandate.domain.decisions import Outcome, PolicyDecision, ReasonCode
from mandate.domain.input import Counterparty
from mandate.policy.engine import evaluate
from tests.support.factories import FUTURE, PAST, make_claims

D = DealState


def _assert_decision(d: PolicyDecision, outcome: Outcome, reason: ReasonCode) -> PolicyDecision:
    assert d.outcome is outcome
    assert d.reason_code is reason
    return d


# ---------------------------------------------------------------------------
# Baseline + decision shape
# ---------------------------------------------------------------------------


def test_baseline_proposal_is_allowed(make_input):
    d = _assert_decision(evaluate(make_input()), Outcome.ALLOW, ReasonCode.OK)
    assert d.matched_rule == "step_13_allow"
    assert d.explanation


def test_decision_shape(make_input):
    pi = make_input()
    d = evaluate(pi)
    assert d.authority_record_id == pi.authority.record.record_id
    assert d.evaluated_at == pi.now
    assert re.fullmatch(r"[0-9a-f]{64}", d.input_digest)


def test_identical_input_yields_identical_decision_bytes(make_input):
    pi = make_input()
    assert evaluate(pi).model_dump_json() == evaluate(pi).model_dump_json()


# ---------------------------------------------------------------------------
# Step 1: schema version
# ---------------------------------------------------------------------------


def test_step01_newer_schema_version_denied(make_input):
    d = evaluate(make_input(schema_version="0.2"))
    _assert_decision(d, Outcome.DENY, ReasonCode.UNKNOWN_SCHEMA_VERSION)
    assert d.matched_rule == "step_01_schema_version"


def test_step01_older_schema_version_denied(make_input):
    d = evaluate(make_input(schema_version="0.0"))
    _assert_decision(d, Outcome.DENY, ReasonCode.UNKNOWN_SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# Step 2: signature claim
# ---------------------------------------------------------------------------


def test_step02_invalid_signature_claim_denied(make_input, make_claim):
    d = evaluate(make_input(claim=make_claim(signature_valid=False)))
    _assert_decision(d, Outcome.DENY, ReasonCode.INVALID_SIGNATURE_CLAIM)
    assert d.matched_rule == "step_02_signature"


def test_step02_valid_signature_claim_passes(make_input, make_claim):
    d = evaluate(make_input(claim=make_claim(signature_valid=True)))
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 3: validity interval + revocation
# ---------------------------------------------------------------------------


def test_step03_revoked_record_denied(make_input, make_record):
    d = evaluate(make_input(record=make_record(status=RecordStatus.REVOKED)))
    _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_REVOKED)
    assert d.matched_rule == "step_03_validity"


def test_step03_expired_status_denied(make_input, make_record):
    d = evaluate(make_input(record=make_record(status=RecordStatus.EXPIRED)))
    _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_EXPIRED)


def test_step03_not_yet_valid_denied(make_input, make_record):
    d = evaluate(make_input(record=make_record(not_before=FUTURE)))
    _assert_decision(d, Outcome.DENY, ReasonCode.NOT_YET_VALID)


def test_step03_past_expires_at_denied(make_input, make_record):
    d = evaluate(make_input(record=make_record(expires_at=PAST)))
    _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_EXPIRED)


def test_step03_boundary_not_before_is_allowed(make_input, make_record):
    d = evaluate(make_input(record=make_record(not_before="2026-01-15T12:00:00Z")))
    assert d.outcome is Outcome.ALLOW


def test_step03_boundary_expires_at_is_allowed(make_input, make_record):
    d = evaluate(make_input(record=make_record(expires_at="2026-01-15T12:00:00Z")))
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 4: delegation chain
# ---------------------------------------------------------------------------


def test_step04_broken_delegation_link_denied(make_input, make_claim, ulid):
    link = DelegationLink(parent_record_id=ulid(), scope_narrowing_valid=False)
    d = evaluate(make_input(claim=make_claim(delegation_chain=[link])))
    _assert_decision(d, Outcome.DENY, ReasonCode.DELEGATION_CHAIN_BROKEN)
    assert d.matched_rule == "step_04_delegation"


def test_step04_valid_delegation_chain_allowed(make_input, make_claim, ulid):
    link = DelegationLink(parent_record_id=ulid(), scope_narrowing_valid=True)
    d = evaluate(make_input(claim=make_claim(delegation_chain=[link])))
    assert d.outcome is Outcome.ALLOW


def test_step04_multi_link_chain_breaks_at_second_link(make_input, make_claim, ulid):
    links = [
        DelegationLink(parent_record_id=ulid(), scope_narrowing_valid=True),
        DelegationLink(parent_record_id=ulid(), scope_narrowing_valid=False),
    ]
    d = evaluate(make_input(claim=make_claim(delegation_chain=links)))
    _assert_decision(d, Outcome.DENY, ReasonCode.DELEGATION_CHAIN_BROKEN)


# ---------------------------------------------------------------------------
# Step 5: audience / counterparty
# ---------------------------------------------------------------------------


def test_step05_audience_mismatch_denied(make_input, make_record, ulid):
    rec = make_record(counterparty_id=ulid())
    d = evaluate(make_input(record=rec, counterparty=Counterparty(id=ulid())))
    _assert_decision(d, Outcome.DENY, ReasonCode.AUDIENCE_MISMATCH)
    assert d.matched_rule == "step_05_audience"


def test_step05_matching_audience_allowed(make_input, make_record, ulid):
    cp = ulid()
    d = evaluate(
        make_input(record=make_record(counterparty_id=cp), counterparty=Counterparty(id=cp))
    )
    assert d.outcome is Outcome.ALLOW


def test_step05_absent_counterparty_skips_check(make_input, make_record, ulid):
    d = evaluate(
        make_input(
            record=make_record(counterparty_id=ulid()),
            counterparty=Counterparty(id=None),
        )
    )
    assert d.outcome is Outcome.ALLOW


def test_step05_unrestricted_record_skips_check(make_input, ulid):
    d = evaluate(make_input(counterparty=Counterparty(id=ulid())))
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 6: prohibited actions (invariant 6)
# ---------------------------------------------------------------------------


def test_step06_prohibited_action_denied_even_when_allowed(
    make_input, make_record, make_deal, make_proposal
):
    deal = make_deal(D.QUOTE_RECEIVED)
    d = evaluate(
        make_input(
            record=make_record(prohibited_actions=[ActionToken.COUNTEROFFER]),
            deal=deal,
            proposal=make_proposal(action="counteroffer", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.ACTION_PROHIBITED)
    assert d.matched_rule == "step_06_prohibited"


# ---------------------------------------------------------------------------
# Step 7: allowed actions
# ---------------------------------------------------------------------------


def test_step07_unknown_action_token_denied(make_input, make_proposal):
    d = evaluate(make_input(proposal=make_proposal(action="open_bank_account")))
    _assert_decision(d, Outcome.DENY, ReasonCode.UNKNOWN_ACTION)
    assert d.matched_rule == "step_07_allowed"


def test_step07_action_not_in_allowlist_denied(make_input, make_record, make_deal, make_proposal):
    deal = make_deal(D.QUOTE_RECEIVED)
    d = evaluate(
        make_input(
            record=make_record(allowed_actions=[ActionToken.REQUEST_QUOTE]),
            deal=deal,
            proposal=make_proposal(action="counteroffer", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.ACTION_NOT_ALLOWED)


# ---------------------------------------------------------------------------
# Step 8: state transition + payment blocks (invariant 10)
# ---------------------------------------------------------------------------


def test_step08_action_invalid_in_current_state_denied(make_input, make_deal, make_proposal):
    deal = make_deal(D.QUOTE_REQUESTED)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="request_quote", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.INVALID_TRANSITION)
    assert d.matched_rule == "step_08_transition"


def test_step08_payment_blocked_by_open_dispute(make_input, make_deal, make_proposal):
    deal = make_deal(D.ACCEPTED, open_disputes=1)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="initiate_payment", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE)


def test_step08_payment_blocked_by_open_approval(make_input, make_deal, make_proposal):
    deal = make_deal(D.ACCEPTED, open_approvals=1)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="initiate_payment", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL)


def test_step08_dispute_precedes_approval_in_block_reason(make_input, make_deal, make_proposal):
    deal = make_deal(D.ACCEPTED, open_disputes=1, open_approvals=1)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="initiate_payment", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE)


def test_step08_capture_payment_allowed_from_payment_pending(make_input, make_deal, make_proposal):
    deal = make_deal(D.PAYMENT_PENDING)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="capture_payment", deal_id=deal.deal_id),
        )
    )
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 9: disclosure allow-list (invariant 9)
# ---------------------------------------------------------------------------


def test_step09_disclosure_field_outside_allowlist_denied(make_input, make_proposal):
    d = evaluate(make_input(proposal=make_proposal(disclosure_fields=["invoice_total"])))
    _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_NOT_ALLOWED)
    assert d.matched_rule == "step_09_disclosure"


def test_step09_allowlisted_disclosure_allowed(make_input, make_record, make_proposal):
    d = evaluate(
        make_input(
            record=make_record(disclosure_fields=["invoice_total"]),
            proposal=make_proposal(disclosure_fields=["invoice_total"]),
        )
    )
    assert d.outcome is Outcome.ALLOW


def test_step09_harmless_field_still_denied(make_input, make_record, make_proposal):
    d = evaluate(
        make_input(
            record=make_record(disclosure_fields=["invoice_total"]),
            proposal=make_proposal(disclosure_fields=["customer_phone"]),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_NOT_ALLOWED)


def test_step09_one_bad_field_among_good_fields_denies(make_input, make_record, make_proposal):
    d = evaluate(
        make_input(
            record=make_record(disclosure_fields=["alpha", "beta"]),
            proposal=make_proposal(disclosure_fields=["beta", "gamma"]),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.DISCLOSURE_NOT_ALLOWED)


# ---------------------------------------------------------------------------
# Step 10: financial exposure (invariant 8)
# ---------------------------------------------------------------------------


def test_step10_exact_cap_allowed(make_input, make_record, make_deal, make_proposal):
    deal = make_deal(D.CHANGE_REQUESTED, committed_minor=99_999)
    d = evaluate(
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=100_000)),
            deal=deal,
            proposal=make_proposal(
                action="approve_change_order",
                deal_id=deal.deal_id,
                amount_minor=1,
                currency="USD",
            ),
        )
    )
    assert d.outcome is Outcome.ALLOW


def test_step10_cap_plus_one_needs_approval(make_input, make_record, make_deal, make_proposal):
    deal = make_deal(D.CHANGE_REQUESTED, committed_minor=99_999)
    d = evaluate(
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=100_000)),
            deal=deal,
            proposal=make_proposal(
                action="approve_change_order",
                deal_id=deal.deal_id,
                amount_minor=2,
                currency="USD",
            ),
        )
    )
    _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.SPEND_CAP_EXCEEDED)
    assert d.matched_rule == "step_10_spend"


def test_step10_cumulative_committed_counts(make_input, make_record, make_deal, make_proposal):
    # committed_minor already carries approved change orders (invariant 8).
    deal = make_deal(D.CHANGE_REQUESTED, committed_minor=60_000)
    d = evaluate(
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=100_000)),
            deal=deal,
            proposal=make_proposal(
                action="approve_change_order",
                deal_id=deal.deal_id,
                amount_minor=40_001,
                currency="USD",
            ),
        )
    )
    _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.SPEND_CAP_EXCEEDED)


def test_step10_currency_mismatch_denied(make_input, make_record, make_deal, make_proposal):
    deal = make_deal(D.CHANGE_REQUESTED, committed_minor=0)
    d = evaluate(
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=100_000)),
            deal=deal,
            proposal=make_proposal(
                action="approve_change_order",
                deal_id=deal.deal_id,
                amount_minor=1,
                currency="EUR",
            ),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.CURRENCY_MISMATCH)


def test_step10_currency_checked_before_cap(make_input, make_record, make_deal, make_proposal):
    # A cross-currency total is not comparable, so the currency check runs
    # inside step 10, before the cap comparison (spec step 10).
    deal = make_deal(D.CHANGE_REQUESTED, committed_minor=99_999)
    d = evaluate(
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=100_000)),
            deal=deal,
            proposal=make_proposal(
                action="approve_change_order",
                deal_id=deal.deal_id,
                amount_minor=1,
                currency="EUR",
            ),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.CURRENCY_MISMATCH)


def test_step10_no_amount_skips_spend_check_even_at_zero_cap(make_input, make_record):
    d = evaluate(make_input(record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=0))))
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 11: negotiation limits
# ---------------------------------------------------------------------------


def test_step11_negotiation_limit_at_cap_denied(make_input, make_deal, make_proposal):
    deal = make_deal(D.NEGOTIATING, negotiated_rounds=10)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="counteroffer", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.NEGOTIATION_LIMIT_REACHED)
    assert d.matched_rule == "step_11_limits"


def test_step11_round_below_cap_allowed(make_input, make_deal, make_proposal):
    deal = make_deal(D.NEGOTIATING, negotiated_rounds=9)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="counteroffer", deal_id=deal.deal_id),
        )
    )
    assert d.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# Step 12: human approval requirement
# ---------------------------------------------------------------------------


def test_step12_human_approval_required_needs_approval(
    make_input, make_record, make_deal, make_proposal
):
    deal = make_deal(D.QUOTE_RECEIVED)
    d = evaluate(
        make_input(
            record=make_record(requires_human_approval_for=[ActionToken.ACCEPT_AGREEMENT]),
            deal=deal,
            proposal=make_proposal(action="accept_agreement", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.APPROVAL_REQUIRED)
    assert d.matched_rule == "step_12_approval"


def test_step12_spend_cap_precedes_approval_requirement(
    make_input, make_record, make_deal, make_proposal
):
    deal = make_deal(D.QUOTE_RECEIVED, committed_minor=99_999)
    d = evaluate(
        make_input(
            record=make_record(
                requires_human_approval_for=[ActionToken.ACCEPT_AGREEMENT],
                spend_cap=SpendCap(currency="USD", amount_minor=100_000),
            ),
            deal=deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=2,
                currency="USD",
            ),
        )
    )
    _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.SPEND_CAP_EXCEEDED)


def test_step12_engine_never_assumes_approval(make_input, make_record):
    d = evaluate(
        make_input(record=make_record(requires_human_approval_for=[ActionToken.REQUEST_QUOTE]))
    )
    _assert_decision(d, Outcome.NEEDS_APPROVAL, ReasonCode.APPROVAL_REQUIRED)


# ---------------------------------------------------------------------------
# Step 13
# ---------------------------------------------------------------------------


def test_step13_allow_only_when_all_prior_checks_pass(make_input):
    d = evaluate(make_input())
    _assert_decision(d, Outcome.ALLOW, ReasonCode.OK)
    assert d.matched_rule == "step_13_allow"


# ---------------------------------------------------------------------------
# Precedence (invariant 6)
# ---------------------------------------------------------------------------


def test_precedence_schema_beats_signature(make_input, make_claim):
    d = evaluate(make_input(schema_version="9.9", claim=make_claim(signature_valid=False)))
    _assert_decision(d, Outcome.DENY, ReasonCode.UNKNOWN_SCHEMA_VERSION)


def test_precedence_signature_beats_prohibition(make_input, make_record, make_claim):
    d = evaluate(
        make_input(
            record=make_record(prohibited_actions=[ActionToken.REQUEST_QUOTE]),
            claim=make_claim(signature_valid=False),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.INVALID_SIGNATURE_CLAIM)


def test_precedence_revoked_beats_perfect_proposal(make_input, make_record):
    d = evaluate(make_input(record=make_record(status=RecordStatus.REVOKED)))
    _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_REVOKED)


def test_precedence_expiry_beats_perfect_proposal(make_input, make_record):
    d = evaluate(make_input(record=make_record(expires_at=PAST)))
    _assert_decision(d, Outcome.DENY, ReasonCode.RECORD_EXPIRED)


def test_precedence_not_yet_valid_beats_perfect_proposal(make_input, make_record):
    d = evaluate(make_input(record=make_record(not_before=FUTURE)))
    _assert_decision(d, Outcome.DENY, ReasonCode.NOT_YET_VALID)


def test_precedence_unknown_action_beats_bad_state(make_input, make_deal, make_proposal):
    deal = make_deal(D.QUOTE_REQUESTED)
    d = evaluate(
        make_input(
            deal=deal,
            proposal=make_proposal(action="not_an_action", deal_id=deal.deal_id),
        )
    )
    _assert_decision(d, Outcome.DENY, ReasonCode.UNKNOWN_ACTION)


# ---------------------------------------------------------------------------
# Reason code coverage (exit criterion: every code has a named test)
# ---------------------------------------------------------------------------

# Every reason_code the engine can produce. MISSING_FIELD and REPLAY_DETECTED
# are boundary-owned (specs/policy-schema.md §Anti-replay): missing fields are
# rejected at PolicyInput construction, replay detection is the boundary's
# seen-request store.
ENGINE_REASON_CODES = frozenset(
    {
        ReasonCode.OK,
        ReasonCode.UNKNOWN_SCHEMA_VERSION,
        ReasonCode.INVALID_SIGNATURE_CLAIM,
        ReasonCode.RECORD_REVOKED,
        ReasonCode.RECORD_EXPIRED,
        ReasonCode.NOT_YET_VALID,
        ReasonCode.DELEGATION_CHAIN_BROKEN,
        ReasonCode.AUDIENCE_MISMATCH,
        ReasonCode.ACTION_PROHIBITED,
        ReasonCode.ACTION_NOT_ALLOWED,
        ReasonCode.UNKNOWN_ACTION,
        ReasonCode.INVALID_TRANSITION,
        ReasonCode.DISCLOSURE_NOT_ALLOWED,
        ReasonCode.SPEND_CAP_EXCEEDED,
        ReasonCode.NEGOTIATION_LIMIT_REACHED,
        ReasonCode.APPROVAL_REQUIRED,
        ReasonCode.PAYMENT_BLOCKED_BY_DISPUTE,
        ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL,
        ReasonCode.CURRENCY_MISMATCH,
        # ADR-0016 content screen (steps 9b / 12b)
        ReasonCode.DISCLOSURE_DETECTED,
        ReasonCode.CONTENT_REVIEW_REQUIRED,
        ReasonCode.HOSTILE_CONTENT_SUSPECTED,
        ReasonCode.CONTENT_SCREEN_UNAVAILABLE,
    }
)


def test_reason_enum_is_engine_codes_plus_boundary_codes():
    assert set(ReasonCode) == set(ENGINE_REASON_CODES) | {
        ReasonCode.MISSING_FIELD,
        ReasonCode.REPLAY_DETECTED,
    }


def test_every_engine_reason_code_is_producible(
    make_input, make_record, make_claim, make_deal, make_proposal, ulid
):
    deal_neg = make_deal(D.QUOTE_RECEIVED, negotiated_rounds=10)
    deal_pay = make_deal(D.ACCEPTED)
    inputs = [
        make_input(),
        make_input(schema_version="0.2"),
        make_input(claim=make_claim(signature_valid=False)),
        make_input(record=make_record(status=RecordStatus.REVOKED)),
        make_input(record=make_record(expires_at=PAST)),
        make_input(record=make_record(not_before=FUTURE)),
        make_input(
            claim=make_claim(
                delegation_chain=[
                    DelegationLink(parent_record_id=ulid(), scope_narrowing_valid=False)
                ]
            )
        ),
        make_input(
            record=make_record(counterparty_id=ulid()),
            counterparty=Counterparty(id=ulid()),
        ),
        make_input(record=make_record(prohibited_actions=[ActionToken.REQUEST_QUOTE])),
        make_input(record=make_record(allowed_actions=[ActionToken.CANCEL_DEAL])),
        make_input(proposal=make_proposal(action="teleport")),
        make_input(deal=make_deal(D.QUOTE_REQUESTED)),
        make_input(proposal=make_proposal(disclosure_fields=["anything"])),
        make_input(
            record=make_record(spend_cap=SpendCap(currency="USD", amount_minor=0)),
            proposal=make_proposal(amount_minor=1),
        ),
        make_input(
            deal=deal_neg,
            proposal=make_proposal(action="counteroffer", deal_id=deal_neg.deal_id),
        ),
        make_input(record=make_record(requires_human_approval_for=[ActionToken.REQUEST_QUOTE])),
        make_input(
            deal=make_deal(D.ACCEPTED, open_disputes=1),
            proposal=make_proposal(action="initiate_payment", deal_id=deal_pay.deal_id),
        ),
        make_input(
            deal=make_deal(D.ACCEPTED, open_approvals=1),
            proposal=make_proposal(action="initiate_payment", deal_id=deal_pay.deal_id),
        ),
        make_input(proposal=make_proposal(amount_minor=1, currency="EUR")),
        # ADR-0016 content screen
        make_input(content=make_claims({"customer_phone": 9_500})),
        make_input(content=make_claims({"customer_phone": 7_500})),
        make_input(content=make_claims(hostility_bp=8_000)),
        make_input(content=make_claims(available=False)),
    ]
    produced = {evaluate(pi).reason_code for pi in inputs}
    assert produced == ENGINE_REASON_CODES


# ---------------------------------------------------------------------------
# Idempotency shape + validation
# ---------------------------------------------------------------------------


def test_identical_proposal_structure_accepted_twice(make_input):
    pi = make_input()
    assert evaluate(pi) == evaluate(pi)


def test_malformed_deal_id_rejected_at_validation(make_proposal):
    with pytest.raises(ValidationError):
        make_proposal(deal_id="not-a-ulid")


def test_malformed_idempotency_key_rejected_at_validation(make_proposal):
    with pytest.raises(ValidationError):
        make_proposal(idempotency_key="x" * 25)


def test_float_amount_rejected_at_validation(make_proposal):
    with pytest.raises(ValidationError):
        make_proposal(amount_minor=10.5)


def test_malformed_record_id_rejected_at_validation(make_record):
    with pytest.raises(ValidationError):
        make_record(record_id="short")
