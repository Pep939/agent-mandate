"""G1 — master differential soundness property (docs/threat-walkthrough.md, gap G1).

The engine (src/mandate/policy/engine.py) is the component we trust to *never
over-authorize*. A code review can miss a subtle over-allow; an independent
re-derivation of the authorization decision cannot share the same control-flow
bug.

``oracle_allows`` re-derives, gate by gate and straight from the PolicyInput
fields, whether the spec (specs/policy-schema.md) authorizes the proposal. It
never calls ``evaluate()`` and never reuses the engine's sequencing. It shares
only the closed *data* definitions (the action vocabulary and the
action->state / payment / negotiation tables) — those are the spec's definitions,
not a decision procedure. What this catches is a divergence in the engine's
*logic or ordering*, which is exactly the failure mode a review of the engine
alone cannot rule out.

Two implications pin the engine to the oracle:

  * soundness (the safety claim):  engine ALLOW  =>  oracle says allow.
    If the engine ever authorizes what the spec does not, this fires.
  * completeness:  oracle says allow  =>  engine ALLOW.
    If the engine over-denies what the spec allows, this fires.

``allowing_inputs`` builds spec-compliant inputs that must be ALLOWed, so the
differential population is guaranteed non-vacuous (Hypothesis will not, on its
own, steer toward the rare all-gates-passing corner of the arbitrary space).
"""

from __future__ import annotations

from datetime import datetime

from hypothesis import given
from hypothesis import strategies as st

from mandate.domain.authority import ActionToken, RecordStatus, SpendCap
from mandate.domain.decisions import Outcome
from mandate.domain.input import Counterparty, PolicyInput
from mandate.domain.state_machine import (
    ACTION_VALID_STATES,
    NEGOTIATION_ACTIONS,
    PAYMENT_ACTIONS,
)
from mandate.policy.engine import evaluate
from tests.property.test_properties import policy_inputs
from tests.support.factories import (
    FUTURE,
    NOW,
    PAST,
    make_claim,
    make_deal,
    make_input,
    make_proposal,
    make_record,
)

TOKENS = list(ActionToken)
_ALL_ACTION_VALUES = frozenset(t.value for t in ActionToken)


def oracle_allows(pi: PolicyInput) -> bool:  # noqa: C901
    """Independent re-derivation of the spec's 13 authorization gates.

    Returns True iff every gate would pass. Does not call ``evaluate()`` and
    does not reuse the engine's control flow; each gate is re-checked directly
    from the PolicyInput fields. See the module docstring on what "independent"
    covers and what it deliberately shares (the closed data definitions).
    """
    record = pi.authority.record
    proposal = pi.proposal
    deal = pi.deal

    # Gate 1 — schema version (hardcoded: the spec pins the supported version).
    if pi.schema_version != "0.1":
        return False

    # Gate 2 — boundary-reported signature claim.
    if not pi.authority.signature_valid:
        return False

    # Gate 3 — status + validity window (inclusive on both ends).
    if pi.authority.status is not RecordStatus.ACTIVE:
        return False
    now = datetime.fromisoformat(pi.now)
    if now < datetime.fromisoformat(record.not_before):
        return False
    if now > datetime.fromisoformat(record.expires_at):
        return False

    # Gate 4 — every delegation link must narrow (not widen) scope.
    if not all(link.scope_narrowing_valid for link in pi.authority.delegation_chain):
        return False

    # Gate 5 — audience / counterparty must match when both are pinned.
    if (
        record.counterparty_id is not None
        and pi.counterparty.id is not None
        and pi.counterparty.id != record.counterparty_id
    ):
        return False

    # Gate 6 — explicit prohibition beats any allowance.
    action_str = proposal.action
    if action_str in {a.value for a in record.prohibited_actions}:
        return False

    # Gate 7 — action must be a known token AND explicitly allowed.
    if action_str not in _ALL_ACTION_VALUES:
        return False
    action = ActionToken(action_str)
    if action not in record.allowed_actions:
        return False

    # Gate 8 — action must be valid in the deal state; payments are blocked by
    # any open dispute or open approval.
    if deal.state not in ACTION_VALID_STATES.get(action, frozenset()):
        return False
    if action in PAYMENT_ACTIONS and (deal.open_disputes > 0 or deal.open_approvals > 0):
        return False

    # Gate 9 — every requested disclosure field must be on the allow-list.
    if not all(field in record.disclosure_fields for field in proposal.disclosure_fields):
        return False

    # Gate 10 — financial exposure: raw currency match, then cumulative cap.
    if proposal.amount_minor is not None:
        if proposal.currency != record.spend_cap.currency:
            return False
        if deal.committed_minor + proposal.amount_minor > record.spend_cap.amount_minor:
            return False

    # Gate 11 — negotiation round limit.
    if action in NEGOTIATION_ACTIONS and deal.negotiated_rounds >= record.max_negotiation_rounds:
        return False

    # Gates 12 + 13 — allow iff the action does not require human approval.
    return action not in record.requires_human_approval_for


@st.composite
def allowing_inputs(draw: st.DrawFn) -> PolicyInput:
    """A spec-compliant PolicyInput that every correct engine must ALLOW.

    Passes all 13 gates by construction, leaving randomness only in dimensions
    that cannot break allowance (the deal state, the amount, the disclosure
    subset, the negotiation rounds). This keeps the differential population
    from being vacuously empty.
    """
    action = draw(st.sampled_from(TOKENS))
    state = draw(st.sampled_from(list(ACTION_VALID_STATES[action])))
    rec = make_record(
        allowed_actions=list(ActionToken),
        prohibited_actions=[],
        requires_human_approval_for=[],
        status=RecordStatus.ACTIVE,
        counterparty_id=None,
        not_before=PAST,
        expires_at=FUTURE,
        spend_cap=SpendCap(currency="USD", amount_minor=10_000_000),
        max_negotiation_rounds=10,
        disclosure_fields=["invoice_total", "customer_phone"],
    )
    deal = make_deal(
        state=state,
        negotiated_rounds=draw(st.integers(min_value=0, max_value=3)),
        committed_minor=0,
        open_disputes=0,
        open_approvals=0,
    )
    proposal = make_proposal(
        action=action.value,
        amount_minor=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=5_000_000))),
        currency="USD",
        disclosure_fields=draw(
            st.lists(st.sampled_from(["invoice_total", "customer_phone"]), max_size=2)
        ),
        deal_id=deal.deal_id,
    )
    return make_input(
        schema_version="0.1",
        now=NOW,
        record=rec,
        claim=make_claim(rec, signature_valid=True, delegation_chain=[]),
        deal=deal,
        proposal=proposal,
        counterparty=Counterparty(id=None),
    )


# ---------------------------------------------------------------------------
# Property 7 (soundness, THE safety claim): the engine never over-authorizes.
# If the engine says ALLOW, the independent oracle must independently agree.
# ---------------------------------------------------------------------------


@given(pi=policy_inputs())
def test_engine_never_over_authorizes(pi: PolicyInput):
    if evaluate(pi).outcome is Outcome.ALLOW:
        assert oracle_allows(pi), (
            f"engine ALLOWed a proposal the spec does not authorize: "
            f"action={pi.proposal.action!r} state={pi.deal.state.value} "
            f"now={pi.now} status={pi.authority.status.value}"
        )


# ---------------------------------------------------------------------------
# Property 8 (completeness): the engine never over-denies. If the independent
# oracle says the spec authorizes the proposal, the engine must say ALLOW.
# ---------------------------------------------------------------------------


@given(pi=policy_inputs())
def test_engine_allows_everything_the_spec_allows(pi: PolicyInput):
    if oracle_allows(pi):
        assert evaluate(pi).outcome is Outcome.ALLOW, (
            f"oracle says allowed but engine did not ALLOW: "
            f"action={pi.proposal.action!r} state={pi.deal.state.value}"
        )


# ---------------------------------------------------------------------------
# Non-vacuity baseline: the constructed inputs are, by construction, allowed by
# the spec (oracle) and by the engine. If this fails, either the strategy is
# broken or the two properties above are running on an empty population.
# ---------------------------------------------------------------------------


@given(pi=allowing_inputs())
def test_allowing_baseline_is_allowed_by_both(pi: PolicyInput):
    assert oracle_allows(pi), "allowing_inputs produced an input the oracle rejects"
    assert evaluate(pi).outcome is Outcome.ALLOW, (
        f"allowing_inputs produced an input the engine did not ALLOW: "
        f"action={pi.proposal.action!r} state={pi.deal.state.value}"
    )
