"""Property 9 (ADR-0016, THE content-screen safety claim): a content screen
can only ever make the engine more careful.

Rank the three outcomes as a ladder — allow (0) is the most permissive,
needs_approval (1) next, deny (2) the least. The property: for any policy
input and any claims a screen could return,

    rank(evaluate(input + claims)) >= rank(evaluate(input))

Adding a classifier's opinion never moves a decision *up* the ladder. The
consequence is the one that matters: a screen that is wrong, miscalibrated,
or prompt-injected can cause a false hold or a false deny, but it can never
hand an agent authority it did not already have (invariants 1 and 11).

A second property pins the reason codes: the four content reason codes never
appear on an ALLOW.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mandate.domain.content import BP_SCALE, ContentClaims, DetectedField
from mandate.domain.decisions import Outcome, ReasonCode
from mandate.domain.input import PolicyInput
from mandate.policy.engine import evaluate
from tests.property.test_properties import policy_inputs
from tests.support.factories import QUESTION_SET_SHA

RANK = {Outcome.ALLOW: 0, Outcome.NEEDS_APPROVAL: 1, Outcome.DENY: 2}

CONTENT_REASON_CODES = frozenset(
    {
        ReasonCode.DISCLOSURE_DETECTED,
        ReasonCode.CONTENT_REVIEW_REQUIRED,
        ReasonCode.HOSTILE_CONTENT_SUSPECTED,
        ReasonCode.CONTENT_SCREEN_UNAVAILABLE,
    }
)

# The whole token space a screen can answer about, plus one the mandate
# vocabulary knows nothing about — a screen must not gain power by inventing
# a field name.
FIELD_TOKENS = st.sampled_from(
    [
        "customer_phone",
        "customer_email",
        "customer_address",
        "invoice_total",
        "price_floor",
        "internal_notes",
        "work_order_id",
        "unknown_token",
    ]
)
BASIS_POINTS = st.integers(min_value=0, max_value=BP_SCALE)


@st.composite
def content_claims(draw: st.DrawFn) -> ContentClaims:
    """Any claim a screen could return, well-formed but otherwise arbitrary."""
    pairs = draw(st.lists(st.tuples(FIELD_TOKENS, BASIS_POINTS), max_size=4))
    deduped: dict[str, int] = dict(pairs)
    return ContentClaims(
        screener=draw(st.sampled_from(["fixture:keyword-0.1", "typesafe:jev-1.13.0"])),
        question_set_sha256=QUESTION_SET_SHA,
        content_chars=draw(st.integers(min_value=0, max_value=64_000)),
        available=draw(st.booleans()),
        detected=[DetectedField(field=f, confidence_bp=bp) for f, bp in sorted(deduped.items())],
        hostility_bp=draw(BASIS_POINTS),
        persuasion_bp=draw(BASIS_POINTS),
        urgency_level=draw(st.integers(min_value=0, max_value=3)),
    )


def _with_content(pi: PolicyInput, claims: ContentClaims) -> PolicyInput:
    proposal = pi.proposal.model_copy(update={"content_sha256": "c" * 64})
    return pi.model_copy(update={"proposal": proposal, "content": claims})


@given(pi=policy_inputs(), claims=content_claims())
def test_content_claims_can_only_narrow(pi: PolicyInput, claims: ContentClaims):
    """The safety claim: claims never move a decision toward allow."""
    before = evaluate(pi).outcome
    after = evaluate(_with_content(pi, claims)).outcome
    assert RANK[after] >= RANK[before], (
        f"content claims loosened the decision: {before.value} -> {after.value}"
    )


@given(pi=policy_inputs(), claims=content_claims())
def test_content_reason_codes_never_accompany_an_allow(pi: PolicyInput, claims: ContentClaims):
    decision = evaluate(_with_content(pi, claims))
    if decision.reason_code in CONTENT_REASON_CODES:
        assert decision.outcome is not Outcome.ALLOW


@given(pi=policy_inputs(), claims=content_claims())
def test_engine_stays_deterministic_with_content(pi: PolicyInput, claims: ContentClaims):
    with_content = _with_content(pi, claims)
    assert evaluate(with_content).model_dump_json() == evaluate(with_content).model_dump_json()


@given(pi=policy_inputs(), claims=content_claims())
def test_an_unavailable_screen_never_allows(pi: PolicyInput, claims: ContentClaims):
    """However clean the rest of the answer looks, a screen that could not
    answer must never leave an allow standing."""
    down = claims.model_copy(update={"available": False})
    assert evaluate(_with_content(pi, down)).outcome is not Outcome.ALLOW


@given(pi=policy_inputs(), claims=content_claims())
def test_unknown_field_tokens_grant_no_power(pi: PolicyInput, claims: ContentClaims):
    """A screen that invents a field token the mandate vocabulary does not
    know can still only narrow — it cannot silently widen the allow-list."""
    invented = claims.model_copy(
        update={"detected": [DetectedField(field="unknown_token", confidence_bp=BP_SCALE)]}
    )
    before = evaluate(pi).outcome
    after = evaluate(_with_content(pi, invented)).outcome
    assert RANK[after] >= RANK[before]
