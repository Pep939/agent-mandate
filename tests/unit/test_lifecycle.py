"""Unit tests for authority lifecycle: status, revocation, delegation chains."""

from __future__ import annotations

from typing import Any

from mandate.domain.authority import (
    ActionToken,
    AuthorityRecord,
    RecordStatus,
    Revocation,
    SignatureBlock,
    SpendCap,
)
from mandate.domain.lifecycle import (
    delegation_violations,
    resolve_status,
    revocation_applies,
    scope_violations,
)
from tests.support.factories import FUTURE, NOW, PAST, make_record


class TestResolveStatus:
    def test_active_within_interval(self):
        assert resolve_status(make_record(), NOW) is RecordStatus.ACTIVE

    def test_expiry_is_strictly_after(self):
        rec = make_record(expires_at=NOW)
        assert resolve_status(rec, NOW) is RecordStatus.ACTIVE
        assert resolve_status(rec, "2026-01-15T12:00:01Z") is RecordStatus.EXPIRED

    def test_recorded_revocation_sticks(self):
        rec = make_record(status=RecordStatus.REVOKED, expires_at=FUTURE)
        assert resolve_status(rec, NOW) is RecordStatus.REVOKED

    def test_verified_signed_revocation_revokes(self):
        rec = make_record()
        assert resolve_status(rec, NOW, revoked=True) is RecordStatus.REVOKED


class TestRevocationApplies:
    def _revocation(self, record: AuthorityRecord, **overrides: Any) -> Revocation:
        defaults: dict[str, Any] = {
            "schema_version": "0.1",
            "revocation_id": "0" * 22 + "0001",
            "record_id": record.record_id,
            "revoked_at": PAST,
        }
        defaults.update(overrides)
        if "signature" not in overrides:
            defaults["signature"] = SignatureBlock(algorithm="Ed25519", key_id="k", value="v")
        return Revocation(**defaults)

    def test_applies_when_ids_match_and_time_arrived(self):
        rec = make_record()
        assert revocation_applies(self._revocation(rec), rec, NOW)

    def test_does_not_apply_to_other_record(self):
        rec = make_record()
        other = self._revocation(rec, record_id=make_record().record_id)
        assert not revocation_applies(other, rec, NOW)

    def test_future_revoked_at_not_yet_effective(self):
        rec = make_record()
        future = self._revocation(rec, revoked_at=FUTURE)
        assert not revocation_applies(future, rec, NOW)

    def test_effective_exactly_at_revoked_at(self):
        rec = make_record()
        exact = self._revocation(rec, revoked_at=NOW)
        assert revocation_applies(exact, rec, NOW)


class TestScopeViolations:
    def test_valid_narrowing_has_no_violations(self):
        parent = make_record()
        child = make_record(
            allowed_actions=[ActionToken.REQUEST_QUOTE],
            spend_cap=SpendCap(currency="USD", amount_minor=100),
            max_negotiation_rounds=2,
            expires_at="2026-12-31T00:00:00Z",
        )
        assert scope_violations(child, parent) == []

    def test_allowed_actions_must_be_subset(self):
        parent = make_record(allowed_actions=[ActionToken.REQUEST_QUOTE])
        child = make_record(allowed_actions=[ActionToken.CANCEL_DEAL])
        assert scope_violations(child, parent) == ["allowed_actions_not_subset"]

    def test_prohibited_actions_must_be_superset(self):
        parent = make_record(prohibited_actions=[ActionToken.CAPTURE_PAYMENT])
        child = make_record(prohibited_actions=[])
        assert scope_violations(child, parent) == ["prohibited_actions_not_superset"]

    def test_currency_mismatch(self):
        parent = make_record()
        child = make_record(spend_cap=SpendCap(currency="EUR", amount_minor=1))
        assert scope_violations(child, parent) == ["spend_cap_currency_mismatch"]

    def test_spend_cap_cannot_exceed_parent(self):
        parent = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1000))
        child = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1001))
        assert scope_violations(child, parent) == ["spend_cap_exceeds_parent"]

    def test_equal_spend_cap_is_fine(self):
        parent = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1000))
        child = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1000))
        assert scope_violations(child, parent) == []

    def test_negotiation_rounds_cannot_exceed_parent(self):
        parent = make_record(max_negotiation_rounds=3)
        child = make_record(max_negotiation_rounds=4)
        assert scope_violations(child, parent) == ["max_negotiation_rounds_exceed_parent"]

    def test_disclosure_fields_must_be_subset(self):
        parent = make_record(disclosure_fields=["a", "b"])
        child = make_record(disclosure_fields=["b", "c"])
        assert scope_violations(child, parent) == ["disclosure_fields_not_subset"]

    def test_approval_gates_must_be_superset(self):
        parent = make_record(requires_human_approval_for=[ActionToken.CAPTURE_PAYMENT])
        child = make_record(requires_human_approval_for=[])
        assert scope_violations(child, parent) == ["approval_gates_not_superset"]

    def test_not_before_cannot_precede_parent(self):
        parent = make_record(not_before="2026-06-01T00:00:00Z")
        child = make_record(not_before=PAST)
        assert scope_violations(child, parent) == ["not_before_earlier_than_parent"]

    def test_cannot_outlive_parent(self):
        parent = make_record(expires_at="2026-06-01T00:00:00Z")
        child = make_record(expires_at=FUTURE)
        assert scope_violations(child, parent) == ["expires_after_parent"]

    def test_counterparty_restriction_cannot_widen(self):
        parent = make_record(counterparty_id="0" * 22 + "0001")
        child = make_record(counterparty_id=None)
        assert scope_violations(child, parent) == ["counterparty_mismatch_with_parent"]
        other = make_record(counterparty_id="0" * 22 + "0002")
        assert scope_violations(other, parent) == ["counterparty_mismatch_with_parent"]

    def test_counterparty_restriction_can_narrow_from_open(self):
        parent = make_record(counterparty_id=None)
        child = make_record(counterparty_id="0" * 22 + "0001")
        assert scope_violations(child, parent) == []

    def test_multiple_violations_all_reported(self):
        parent = make_record(
            allowed_actions=[ActionToken.REQUEST_QUOTE],
            spend_cap=SpendCap(currency="USD", amount_minor=100),
            expires_at="2026-03-01T00:00:00Z",
        )
        child = make_record(
            allowed_actions=[ActionToken.CANCEL_DEAL],
            spend_cap=SpendCap(currency="USD", amount_minor=999),
            expires_at=FUTURE,
        )
        assert scope_violations(child, parent) == [
            "allowed_actions_not_subset",
            "spend_cap_exceeds_parent",
            "expires_after_parent",
        ]


class TestDelegationViolations:
    def _chain(
        self,
        grandparent: AuthorityRecord,
        parent: AuthorityRecord,
        child: AuthorityRecord,
    ) -> dict[str, AuthorityRecord]:
        return {
            grandparent.record_id: grandparent,
            parent.record_id: parent,
            child.record_id: child,
        }

    def _valid_child(self, parent: AuthorityRecord, **overrides: Any) -> AuthorityRecord:
        defaults: dict[str, Any] = {
            "parent_record_id": parent.record_id,
            "allowed_actions": [ActionToken.REQUEST_QUOTE],
            "spend_cap": SpendCap(currency="USD", amount_minor=100),
            "max_negotiation_rounds": 1,
        }
        defaults.update(overrides)
        return make_record(**defaults)

    def test_valid_chain_has_no_violations(self):
        gp = make_record()
        parent = self._valid_child(gp)
        child = self._valid_child(parent, allowed_actions=[ActionToken.REQUEST_QUOTE])
        records = self._chain(gp, parent, child)
        assert delegation_violations(child, records) == []

    def test_unresolvable_parent(self):
        parent = make_record()
        child = self._valid_child(parent)
        assert delegation_violations(child, {}) == [f"unresolvable_parent:{parent.record_id}"]

    def test_cycle_detected(self):
        a_id, b_id = "0" * 22 + "aaaa", "0" * 22 + "bbbb"
        a = make_record(record_id=a_id, parent_record_id=b_id)
        b = make_record(record_id=b_id, parent_record_id=a_id)
        records = {a_id: a, b_id: b}
        violations = delegation_violations(a, records)
        # the walk starts at a, follows a→b, then b→a closes the loop at a
        assert violations == ["cycle_at:" + a_id]

    def test_scope_violation_reported_with_parent_id(self):
        parent = make_record(spend_cap=SpendCap(currency="USD", amount_minor=1000))
        child = self._valid_child(parent, spend_cap=SpendCap(currency="USD", amount_minor=1001))
        records = {parent.record_id: parent}
        assert delegation_violations(child, records) == [
            f"{parent.record_id}:spend_cap_exceeds_parent"
        ]

    def test_violation_at_second_hop_located(self):
        gp = make_record()
        parent = self._valid_child(gp)
        child = self._valid_child(
            parent,
            allowed_actions=[ActionToken.CANCEL_DEAL],  # not in parent's set
        )
        records = self._chain(gp, parent, child)
        assert delegation_violations(child, records) == [
            f"{parent.record_id}:allowed_actions_not_subset"
        ]

    def test_recorded_revoked_ancestor_invalidates_descendants(self):
        gp = make_record(status=RecordStatus.REVOKED)
        parent = self._valid_child(gp)
        child = self._valid_child(parent)
        records = self._chain(gp, parent, child)
        assert delegation_violations(child, records, now=NOW) == [
            f"ancestor_revoked:{gp.record_id}"
        ]

    def test_expired_ancestor_invalidates_descendants(self):
        # Narrowing is transitive: a parent cannot outlive its parent, so an
        # expired grandparent implies the parent is expired too — both are
        # reported, innermost hop first (invariant 7).
        gp = make_record(expires_at="2026-01-14T00:00:00Z")  # before NOW, after PAST
        parent = self._valid_child(gp, expires_at="2026-01-14T00:00:00Z")
        child = self._valid_child(parent, expires_at="2026-01-13T00:00:00Z")
        records = self._chain(gp, parent, child)
        assert delegation_violations(child, records, now=NOW) == [
            f"ancestor_expired:{parent.record_id}",
            f"ancestor_expired:{gp.record_id}",
        ]

    def test_no_violations_without_now_ignores_ancestor_time(self):
        gp = make_record(expires_at="2026-01-14T00:00:00Z")
        parent = self._valid_child(gp, expires_at="2026-01-14T00:00:00Z")
        child = self._valid_child(parent, expires_at="2026-01-13T00:00:00Z")
        records = self._chain(gp, parent, child)
        assert delegation_violations(child, records) == []

    def test_self_parent_is_a_cycle(self):
        own = make_record().record_id
        rec2 = make_record(record_id=own, parent_record_id=own)
        records = {own: rec2}
        assert delegation_violations(rec2, records) == [f"cycle_at:{own}"]

    def test_root_record_with_no_parent_is_trivially_valid(self):
        rec = make_record()
        assert delegation_violations(rec, {}) == []
