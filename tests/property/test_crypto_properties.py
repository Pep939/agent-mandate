"""Property tests for canonicalization and signing (invariant 13)."""

from __future__ import annotations

import json

from hypothesis import given
from hypothesis import strategies as st

from mandate.crypto import signing
from mandate.crypto.canonicalization import canonical_bytes, canonical_sha256_hex
from mandate.policy.engine import evaluate
from tests.support.factories import make_input, make_proposal

_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=8)

json_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    _text,
)

json_value = st.recursive(
    json_leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(_text.filter(lambda s: s), children, max_size=5),
    ),
    max_leaves=12,
)


def _reorder(value):
    """Deep copy with dict key insertion order reversed at every level."""
    if isinstance(value, dict):
        return {k: _reorder(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reorder(item) for item in value]
    return value


@given(json_value)
def test_canonical_bytes_deterministic_and_key_order_invariant(value):
    assert canonical_bytes(value) == canonical_bytes(value)
    assert canonical_bytes(value) == canonical_bytes(_reorder(value))


@given(json_value)
def test_canonical_bytes_is_valid_json_with_same_structure(value):
    parsed = json.loads(canonical_bytes(value))
    assert parsed == value


@given(st.binary(min_size=0, max_size=256))
def test_signing_is_deterministic_per_key(payload):
    private_key, _ = signing.generate_keypair()
    assert signing.sign(private_key, payload) == signing.sign(private_key, payload)


@given(st.integers(min_value=0, max_value=10_000_000))
def test_engine_input_digest_agrees_with_shared_canonicalizer(amount: int):
    deal = make_input().deal
    pi = make_input(
        deal=deal,
        proposal=make_proposal(
            action="accept_agreement", deal_id=deal.deal_id, amount_minor=amount, currency="USD"
        ),
    )
    decision = evaluate(pi)
    assert decision.input_digest == canonical_sha256_hex(pi.model_dump(mode="json"))
