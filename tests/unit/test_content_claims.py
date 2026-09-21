"""The ContentClaims domain model (ADR-0016).

What is pinned here: claims are integers (no floats reach the domain), the
screener is always a pinned version, `undeclared` is the deterministic
comparison the engine runs against the mandate's allow-list, and a claim
cannot exist without the digest of what was screened.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mandate.application.anti_replay import proposal_digest
from mandate.crypto.canonicalization import canonical_bytes
from mandate.domain.content import BP_SCALE, ContentClaims, DetectedField
from mandate.domain.input import PolicyInput
from tests.support.factories import (
    CONTENT_SHA,
    QUESTION_SET_SHA,
    make_claims,
    make_input,
    make_proposal,
)


class TestDetectedField:
    def test_basis_points_are_integers(self):
        with pytest.raises(ValidationError):
            DetectedField(field="customer_phone", confidence_bp=0.5)  # type: ignore[arg-type]

    def test_basis_points_bounded(self):
        DetectedField(field="customer_phone", confidence_bp=BP_SCALE)
        with pytest.raises(ValidationError):
            DetectedField(field="customer_phone", confidence_bp=BP_SCALE + 1)
        with pytest.raises(ValidationError):
            DetectedField(field="customer_phone", confidence_bp=-1)

    def test_field_token_is_snake_case(self):
        DetectedField(field="customer_phone", confidence_bp=1)
        for bad in ("Customer Phone", "customer-phone", "2fast", "", "x" * 65):
            with pytest.raises(ValidationError):
                DetectedField(field=bad, confidence_bp=1)


class TestContentClaims:
    def test_screener_must_be_pinned(self):
        make_claims(screener="typesafe:jev-1.13.0")
        for floating in ("jev-latest", "typesafe:latest", "typesafe:jev-latest"):
            with pytest.raises(ValidationError, match="pinned"):
                make_claims(screener=floating)

    def test_screener_must_be_named(self):
        with pytest.raises(ValidationError):
            make_claims(screener="   ")

    def test_question_set_digest_must_be_sha256(self):
        with pytest.raises(ValidationError):
            ContentClaims(screener="fixture:test-0.1", question_set_sha256="nope", content_chars=1)

    def test_duplicate_detected_field_rejected(self):
        with pytest.raises(ValidationError, match="twice"):
            ContentClaims(
                screener="fixture:test-0.1",
                question_set_sha256=QUESTION_SET_SHA,
                content_chars=1,
                detected=[
                    DetectedField(field="customer_phone", confidence_bp=10),
                    DetectedField(field="customer_phone", confidence_bp=20),
                ],
            )

    def test_urgency_bounded(self):
        make_claims(urgency_level=3)
        with pytest.raises(ValidationError):
            make_claims(urgency_level=4)

    def test_negative_content_length_rejected(self):
        with pytest.raises(ValidationError):
            ContentClaims(
                screener="fixture:test-0.1",
                question_set_sha256=QUESTION_SET_SHA,
                content_chars=-1,
            )

    def test_frozen(self):
        claims = make_claims({"customer_phone": 100})
        with pytest.raises(ValidationError):
            claims.hostility_bp = 1  # type: ignore[misc]

    def test_canonical_bytes_are_stable(self):
        a = make_claims({"customer_phone": 9_000, "invoice_total": 100})
        b = make_claims({"invoice_total": 100, "customer_phone": 9_000})
        assert canonical_bytes(a.model_dump(mode="json")) == canonical_bytes(
            b.model_dump(mode="json")
        )


class TestUndeclared:
    def test_allowlisted_fields_are_not_leaks(self):
        claims = make_claims({"invoice_total": 9_900})
        assert claims.undeclared(["invoice_total"]) == []

    def test_fields_outside_the_allowlist_are_leaks(self):
        claims = make_claims({"customer_phone": 9_900})
        leaks = claims.undeclared(["invoice_total"])
        assert [leak.field for leak in leaks] == ["customer_phone"]

    def test_result_is_sorted_for_determinism(self):
        claims = make_claims({"customer_phone": 10, "invoice_total": 20, "work_order_id": 30})
        assert [leak.field for leak in claims.undeclared([])] == [
            "customer_phone",
            "invoice_total",
            "work_order_id",
        ]

    def test_empty_claims_have_no_leaks(self):
        assert make_claims().undeclared([]) == []


class TestPolicyInputBinding:
    def test_claims_require_the_content_digest(self):
        """Claims about content that the proposal does not name are
        unconstructible: the chain must always be able to say what was
        screened."""
        pi = make_input()
        payload = pi.model_dump(mode="json")
        payload["content"] = make_claims().model_dump(mode="json")
        payload["proposal"]["content_sha256"] = None
        with pytest.raises(ValidationError, match="content_sha256"):
            PolicyInput.model_validate(payload)

    def test_factory_attaches_the_digest(self):
        pi = make_input(content=make_claims())
        assert pi.proposal.content_sha256 == CONTENT_SHA

    def test_digest_without_claims_is_allowed(self):
        pi = make_input(proposal=make_proposal(content_sha256=CONTENT_SHA))
        assert pi.content is None

    def test_malformed_digest_rejected(self):
        with pytest.raises(ValidationError):
            make_proposal(content_sha256="not-a-digest")

    def test_content_changes_the_proposal_digest(self):
        """The screened bytes are bound to the proposal, so re-sending the
        same action with different content is a different proposal for the
        anti-replay gate (ADR-0007 + ADR-0016)."""
        base = make_proposal()
        with_content = base.model_copy(update={"content_sha256": CONTENT_SHA})
        pi_a = make_input(proposal=base)
        pi_b = make_input(proposal=with_content)
        assert proposal_digest(pi_a) != proposal_digest(pi_b)
