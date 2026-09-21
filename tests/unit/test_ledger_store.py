"""Unit tests for InMemoryLedgerStore (ADR-0008/0009).

Covers the transactional commit unit: the policy_decision event is always
appended (invariant 5), transitions only on ALLOW against stored state
(invariant 3), and the seen-store is written with the commit.
"""

from __future__ import annotations

import pytest

from mandate.application.anti_replay import proposal_digest
from mandate.application.services import process_request
from mandate.crypto.canonicalization import revocation_signing_payload
from mandate.crypto.signing import make_approval_record
from mandate.crypto.verification import verify_revocation
from mandate.domain.approvals import ApprovalStatus
from mandate.domain.authority import Revocation, SignatureBlock
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.decisions import Outcome
from mandate.domain.events import GENESIS_HASH, EventType
from mandate.domain.input import ActorKind
from mandate.domain.lifecycle import revocation_applies
from mandate.ledger.store import (
    ApprovalDecision,
    ApprovalRequest,
    CommitOutcome,
    InMemoryLedgerStore,
    RevocationRequest,
    TransitionRequest,
)
from tests.support.factories import (
    FUTURE,
    NOW,
    PAST,
    make_deal,
    make_input,
    make_proposal,
    make_record,
    make_signer,
    new_ulid,
)

RECORDED = "2026-01-15T12:00:01Z"


def _setup(state=DealState.DRAFT, **overrides):
    store = InMemoryLedgerStore()
    deal = make_deal(state=state, **overrides)
    store.create_deal(deal, PAST)
    return store, deal, make_signer()


def _input_for(deal, record=None, **overrides):
    defaults = {"deal": deal, "proposal": make_proposal(deal_id=deal.deal_id)}
    defaults.update(overrides)
    return make_input(record=record, **defaults)


def _open_approval(store, deal, signer, record=None):
    """Escalate an over-cap accept_agreement, returning the Approval row."""
    pi = _input_for(
        deal,
        record=record,
        proposal=make_proposal(
            action="accept_agreement",
            deal_id=deal.deal_id,
            amount_minor=10**9,
            currency="USD",
        ),
    )
    process_request(pi, store, signer, recorded_at=RECORDED)
    approvals = store.approvals_for(deal.deal_id)
    assert len(approvals) == 1
    return pi, approvals[0]


def _approval_req(deal, approval, operation, **overrides):
    record = None
    if operation is ApprovalDecision.GRANTED:
        record = make_approval_record(
            approval_record_id=new_ulid(),
            deal_id=deal.deal_id,
            request_id=approval.request_id,
            parent_authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            currency=approval.currency,
            proposal_digest=approval.proposal_digest,
            issued_at=NOW,
            signer=make_signer(),
        )
    defaults = {
        "deal_id": deal.deal_id,
        "approval_id": approval.approval_id,
        "command_id": new_ulid(),
        "operation": operation,
        "actor_kind": ActorKind.PRINCIPAL,
        "actor_id": new_ulid(),
        "authority_record_id": approval.authority_record_id,
        "action": approval.action,
        "amount_minor": approval.amount_minor,
        "occurred_at": NOW,
        "recorded_at": RECORDED,
        "decided_by": approval.authority_record_id,
        "approval_record": record,
    }
    defaults.update(overrides)
    return ApprovalRequest(**defaults)


class TestCreateDeal:
    def test_create_and_get(self):
        store, deal, _ = _setup()
        assert store.get_deal(deal.deal_id) == deal
        assert store.get_deal_created_at(deal.deal_id) == PAST

    def test_duplicate_create_raises(self):
        store, deal, _ = _setup()
        with pytest.raises(ValueError):
            store.create_deal(make_deal(deal_id=deal.deal_id), PAST)

    def test_unknown_deal_is_none(self):
        store, _, _ = _setup()
        assert store.get_deal(new_ulid()) is None


class TestDealLinks:
    def test_link_and_list(self):
        store, deal, _ = _setup()
        record = make_record()
        store.put_record(record)
        store.link_deal_record(deal.deal_id, record.record_id, PAST)
        assert store.list_deal_links() == {deal.deal_id: record.record_id}

    def test_relink_same_pair_is_idempotent(self):
        store, deal, _ = _setup()
        record = make_record()
        store.put_record(record)
        store.link_deal_record(deal.deal_id, record.record_id, PAST)
        store.link_deal_record(deal.deal_id, record.record_id, PAST)
        assert store.list_deal_links() == {deal.deal_id: record.record_id}

    def test_relink_to_different_record_raises(self):
        store, deal, _ = _setup()
        first = make_record()
        second = make_record()
        store.put_record(first)
        store.link_deal_record(deal.deal_id, first.record_id, PAST)
        with pytest.raises(ValueError, match="already linked"):
            store.link_deal_record(deal.deal_id, second.record_id, PAST)
        assert store.list_deal_links() == {deal.deal_id: first.record_id}


class TestCommitRequest:
    def test_allow_appends_decision_and_transition(self):
        store, deal, signer = _setup()
        result = process_request(_input_for(deal), store, signer, recorded_at=RECORDED)
        assert result.verdict.outcome.value == "pass"
        assert result.decision is not None
        assert result.decision.outcome is Outcome.ALLOW
        assert result.commit is not None
        assert result.commit.outcome is CommitOutcome.COMMITTED

        events = store.events_for(deal.deal_id)
        assert len(events) == 2
        assert events[0].event_type is EventType.POLICY_DECISION
        assert events[1].event_type is EventType.STATE_TRANSITION
        assert events[0].sequence_number == 0
        assert events[1].sequence_number == 1
        assert events[0].previous_event_hash == GENESIS_HASH
        assert events[1].previous_event_hash == events[0].event_hash

        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.QUOTE_REQUESTED

    def test_deny_appends_decision_only(self):
        store, deal, signer = _setup()
        pi = _input_for(
            deal,
            proposal=make_proposal(action="utterly_unknown_action", deal_id=deal.deal_id),
        )
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.decision is not None
        assert result.decision.outcome is Outcome.DENY

        events = store.events_for(deal.deal_id)
        assert len(events) == 1
        assert events[0].event_type is EventType.POLICY_DECISION
        assert events[0].payload["outcome"] == "deny"
        assert store.get_deal(deal.deal_id) == deal

    def test_needs_approval_opens_approval(self):
        # accept_agreement is valid from QUOTE_RECEIVED; the amount blows
        # through the $1,000.00 spend cap, which escalates to approval
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        pi = _input_for(
            deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=10**9,
                currency="USD",
            ),
        )
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.decision is not None
        assert result.decision.outcome is Outcome.NEEDS_APPROVAL

        # ADR-0010: the escalation appends the decision AND an approval
        # "required" event, and opens the approval on the deal row.
        events = store.events_for(deal.deal_id)
        assert len(events) == 2
        assert events[0].event_type is EventType.POLICY_DECISION
        assert events[1].event_type is EventType.APPROVAL
        assert events[1].payload["operation"] == "required"

        approvals = store.approvals_for(deal.deal_id)
        assert len(approvals) == 1
        assert approvals[0].status is ApprovalStatus.PENDING
        assert approvals[0].request_id == pi.request_id
        assert approvals[0].proposal_digest == proposal_digest(pi)

        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.QUOTE_RECEIVED  # state unchanged
        assert new_deal.open_approvals == 1

    def test_stored_state_is_source_of_truth(self):
        # boundary claims DRAFT, but the stored deal is already CAPTURED
        store, deal, signer = _setup(state=DealState.CAPTURED)
        stale_claim = make_deal(state=DealState.DRAFT, deal_id=deal.deal_id)
        pi = make_input(deal=stale_claim, proposal=make_proposal(deal_id=deal.deal_id))
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        # the engine evaluated the claimed (DRAFT) deal → ALLOW
        assert result.decision is not None
        assert result.decision.outcome is Outcome.ALLOW
        # but the store rechecks the stored state and aborts
        assert result.commit is not None
        assert result.commit.outcome is CommitOutcome.STALE_STATE
        assert store.events_for(deal.deal_id) == ()
        assert store.get_deal(deal.deal_id) == deal

    def test_deal_not_found(self):
        store, _, signer = _setup()
        other = make_deal(state=DealState.DRAFT, deal_id=new_ulid())
        pi = make_input(deal=other, proposal=make_proposal(deal_id=other.deal_id))
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.commit is not None
        assert result.commit.outcome is CommitOutcome.DEAL_NOT_FOUND

    def test_seen_entries_written_with_commit(self):
        store, deal, signer = _setup()
        pi = _input_for(deal)
        process_request(pi, store, signer, recorded_at=RECORDED)
        assert store.seen_request(pi.request_id)
        assert store.nonce_owner(pi.authority.record.nonce) == pi.authority.record.record_id
        stored = store.decision_for(pi.proposal.idempotency_key)
        assert stored is not None
        assert stored[1].outcome is Outcome.ALLOW

    def test_record_persisted_with_commit(self):
        store, deal, signer = _setup()
        pi = _input_for(deal)
        process_request(pi, store, signer, recorded_at=RECORDED)
        assert store.get_record(pi.authority.record.record_id) == pi.authority.record

    def test_events_are_signed_by_gateway(self):
        from mandate.crypto.signing import b64url_decode
        from mandate.domain.events import event_signing_bytes

        store, deal, signer = _setup()
        process_request(_input_for(deal), store, signer, recorded_at=RECORDED)
        for event in store.events_for(deal.deal_id):
            assert event.signature.key_id == signer.key_id
            assert event.signature.algorithm == "Ed25519"
            signer.public_key.verify(
                b64url_decode(event.signature.value), event_signing_bytes(event)
            )

    def test_denied_record_still_persisted(self):
        store, deal, signer = _setup()
        pi = _input_for(
            deal,
            proposal=make_proposal(action="nope", deal_id=deal.deal_id),
        )
        process_request(pi, store, signer, recorded_at=RECORDED)
        assert store.get_record(pi.authority.record.record_id) is not None


class TestCommitApproval:
    def test_grant_applies_transition_and_closes_approval(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, signer)
        assert store.get_deal(deal.deal_id).open_approvals == 1

        result = store.commit_approval(
            _approval_req(deal, approval, ApprovalDecision.GRANTED), signer
        )
        assert result.outcome is CommitOutcome.COMMITTED

        events = store.events_for(deal.deal_id)
        # decision + required (2) + granted + transition (2)
        assert [e.event_type for e in events[-2:]] == [
            EventType.APPROVAL,
            EventType.STATE_TRANSITION,
        ]
        assert events[-2].payload["operation"] == "granted"

        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.AGREED
        assert new_deal.open_approvals == 0

        stored = store.get_approval(approval.approval_id)
        assert stored is not None
        assert stored.status is ApprovalStatus.GRANTED
        assert stored.command_id is not None

    def test_deny_appends_denied_event_and_closes(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, signer)

        result = store.commit_approval(
            _approval_req(
                deal,
                approval,
                ApprovalDecision.DENIED,
                deny_reason="amount too high",
            ),
            signer,
        )
        assert result.outcome is CommitOutcome.COMMITTED

        events = store.events_for(deal.deal_id)
        assert events[-1].event_type is EventType.APPROVAL
        assert events[-1].payload["operation"] == "denied"
        assert events[-1].payload["deny_reason"] == "amount too high"

        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.QUOTE_RECEIVED  # unchanged
        assert new_deal.open_approvals == 0
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.DENIED

    def test_second_decision_is_already_applied(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, signer)
        req = _approval_req(deal, approval, ApprovalDecision.DENIED)
        assert store.commit_approval(req, signer).outcome is CommitOutcome.COMMITTED
        again = store.commit_approval(req, signer)
        assert again.outcome is CommitOutcome.ALREADY_APPLIED
        assert len(store.events_for(deal.deal_id)) == 3  # decision+required+denied

    def test_grant_unknown_action_is_stale_state(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, signer)
        result = store.commit_approval(
            _approval_req(deal, approval, ApprovalDecision.GRANTED, action="utterly_bogus"),
            signer,
        )
        assert result.outcome is CommitOutcome.STALE_STATE
        assert store.get_deal(deal.deal_id).open_approvals == 1  # unchanged

    def test_grant_requires_signed_record(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, signer)
        req = _approval_req(deal, approval, ApprovalDecision.GRANTED, approval_record=None)
        with pytest.raises(ValueError):
            store.commit_approval(req, signer)

    def test_unknown_approval(self):
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        req = _approval_req(
            deal,
            _fake_approval(deal),
            ApprovalDecision.DENIED,
        )
        assert store.commit_approval(req, signer).outcome is CommitOutcome.APPROVAL_NOT_FOUND


def _fake_approval(deal):
    from mandate.domain.approvals import Approval as _A
    from mandate.domain.decisions import ReasonCode

    return _A(
        approval_id=new_ulid(),
        deal_id=deal.deal_id,
        request_id=new_ulid(),
        authority_record_id=new_ulid(),
        action="accept_agreement",
        amount_minor=10**9,
        currency="USD",
        proposal_digest=new_ulid(),
        reason_code=ReasonCode.APPROVAL_REQUIRED,
        status=ApprovalStatus.PENDING,
        decided_by=None,
        decided_at=None,
        command_id=None,
        created_at=PAST,
    )


def _revoke(store, record, revoked_at=PAST):
    store.put_revocation(
        Revocation(
            schema_version="0.1",
            revocation_id=new_ulid(),
            record_id=record.record_id,
            revoked_at=revoked_at,
            signature=SignatureBlock(algorithm="Ed25519", key_id="k", value="v"),
        )
    )


def _signed_revocation(record, signer, revoked_at=PAST):
    unsigned = Revocation(
        schema_version="0.1",
        revocation_id=new_ulid(),
        record_id=record.record_id,
        revoked_at=revoked_at,
        signature=SignatureBlock(algorithm="Ed25519", key_id="k", value=""),
    )
    return unsigned.model_copy(
        update={
            "signature": SignatureBlock(
                algorithm="Ed25519",
                key_id=signer.key_id,
                value=signer.sign_bytes(revocation_signing_payload(unsigned)),
            )
        }
    )


def _revocation_req(deal, record, signer, **overrides):
    defaults = {
        "deal_id": deal.deal_id,
        "revocation": _signed_revocation(record, signer),
        "command_id": new_ulid(),
        "actor_kind": ActorKind.PRINCIPAL,
        "actor_id": new_ulid(),
        "occurred_at": NOW,
        "recorded_at": RECORDED,
    }
    defaults.update(overrides)
    return RevocationRequest(**defaults)


class TestCommitRevocation:
    """ADR-0014: a revocation is an authority decision, so it is a signed
    event on the linked deal's chain — not just a side-table row. Retries
    and double revocations are idempotent no-ops (invariant 14)."""

    def _setup_with_record(self):
        # QUOTE_RECEIVED: accept_agreement (the escalation action) is valid
        # from here
        store, deal, signer = _setup(state=DealState.QUOTE_RECEIVED)
        record = make_record()
        store.put_record(record)
        return store, deal, record, signer

    def test_revocation_appends_signed_chain_event(self):
        store, deal, record, signer = self._setup_with_record()
        result = store.commit_revocation(_revocation_req(deal, record, signer), signer)
        assert result.outcome is CommitOutcome.COMMITTED

        events = store.events_for(deal.deal_id)
        assert len(events) == 1
        event = events[0]
        assert event.event_type is EventType.REVOCATION
        assert event.sequence_number == 0
        assert event.previous_event_hash == GENESIS_HASH
        assert event.authority_record_id == record.record_id
        assert event.actor_kind is ActorKind.PRINCIPAL

        stored = Revocation.model_validate(event.payload["revocation"])
        assert stored == store.list_revocations([record.record_id])[0]
        assert verify_revocation(stored, signer.public_key).valid
        assert revocation_applies(stored, record, NOW)

    def test_retry_same_command_is_already_applied(self):
        store, deal, record, signer = self._setup_with_record()
        req = _revocation_req(deal, record, signer)
        assert store.commit_revocation(req, signer).outcome is CommitOutcome.COMMITTED
        again = store.commit_revocation(req, signer)
        assert again.outcome is CommitOutcome.ALREADY_APPLIED
        assert len(store.events_for(deal.deal_id)) == 1

    def test_second_revocation_of_same_record_is_already_applied(self):
        store, deal, record, signer = self._setup_with_record()
        assert store.commit_revocation(_revocation_req(deal, record, signer), signer).outcome is (
            CommitOutcome.COMMITTED
        )
        again = store.commit_revocation(_revocation_req(deal, record, signer), signer)
        assert again.outcome is CommitOutcome.ALREADY_APPLIED
        assert len(store.events_for(deal.deal_id)) == 1
        assert len(store.list_revocations([record.record_id])) == 1

    def test_unknown_deal_is_deal_not_found(self):
        store, deal, record, signer = self._setup_with_record()
        result = store.commit_revocation(
            _revocation_req(deal, record, signer, deal_id=new_ulid()), signer
        )
        assert result.outcome is CommitOutcome.DEAL_NOT_FOUND
        assert store.events_for(deal.deal_id) == ()

    def test_unknown_record_is_record_not_found(self):
        store, deal, _record, signer = self._setup_with_record()
        other = make_record()
        result = store.commit_revocation(_revocation_req(deal, other, signer), signer)
        assert result.outcome is CommitOutcome.RECORD_NOT_FOUND
        assert store.events_for(deal.deal_id) == ()

    def test_grant_recheck_sees_committed_revocation(self):
        store, deal, _record, signer = self._setup_with_record()
        _, approval = _open_approval(store, deal, signer, record=_record)
        result = store.commit_revocation(_revocation_req(deal, _record, signer), signer)
        assert result.outcome is CommitOutcome.COMMITTED
        req = _approval_req(deal, approval, ApprovalDecision.GRANTED)
        result = store.commit_approval(req, signer)
        assert result.outcome is CommitOutcome.COMMITTED
        events = store.events_for(deal.deal_id)
        assert events[-1].payload["operation"] == "denied"
        assert "revoked" in events[-1].payload["deny_reason"]
        assert store.get_deal(deal.deal_id).state is DealState.QUOTE_RECEIVED


class TestGrantRecheck:
    """ADR-0010 steps 2-3: a grant is rechecked against the live ledger at
    decision time. A failed recheck becomes a logged deny that closes the
    approval (invariants 3 and 7) — never a silent grant, never an abort."""

    def _forced_deny(self, store, deal, approval, **overrides):
        req = _approval_req(deal, approval, ApprovalDecision.GRANTED, **overrides)
        result = store.commit_approval(req, make_signer())
        assert result.outcome is CommitOutcome.COMMITTED
        events = store.events_for(deal.deal_id)
        assert events[-1].event_type is EventType.APPROVAL
        assert events[-1].payload["operation"] == "denied"
        transitions = [e for e in events if e.event_type is EventType.STATE_TRANSITION]
        assert all(e.payload.get("to_state") != "AGREED" for e in transitions)
        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.open_approvals == 0
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.DENIED
        return req, result, events

    def test_grant_forced_deny_when_parent_revoked(self):
        store, deal, _ = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, make_signer())
        _revoke(store, store.get_record(approval.authority_record_id))

        req, _, events = self._forced_deny(store, deal, approval)
        assert "no longer current" in events[-1].payload["deny_reason"]
        assert "revoked" in events[-1].payload["deny_reason"]
        assert store.get_deal(deal.deal_id).state is DealState.QUOTE_RECEIVED

        # the closed approval is not re-decidable
        again = store.commit_approval(req, make_signer())
        assert again.outcome is CommitOutcome.ALREADY_APPLIED

    def test_grant_forced_deny_when_parent_expired(self):
        store, deal, _ = _setup(state=DealState.QUOTE_RECEIVED)
        # active at proposal time (now == expires_at is still valid), expired
        # by the boundary-supplied decision time
        _, approval = _open_approval(store, deal, make_signer(), record=make_record(expires_at=NOW))

        _, _, events = self._forced_deny(store, deal, approval, occurred_at=FUTURE)
        assert "no longer current" in events[-1].payload["deny_reason"]
        assert "expired" in events[-1].payload["deny_reason"]
        assert store.get_deal(deal.deal_id).state is DealState.QUOTE_RECEIVED

    def test_grant_forced_deny_when_parent_missing(self):
        store, deal, _ = _setup(state=DealState.QUOTE_RECEIVED)
        approval = _fake_approval(deal)  # references a record the store never saw
        store._approvals[approval.approval_id] = approval

        _, _, events = self._forced_deny(store, deal, approval)
        assert "missing from the ledger" in events[-1].payload["deny_reason"]

    def test_grant_forced_deny_when_transition_stale(self):
        store, deal, _ = _setup(state=DealState.QUOTE_RECEIVED)
        _, approval = _open_approval(store, deal, make_signer())
        # the deal moves on without the approval: the boundary cancels it
        cancel = TransitionRequest(
            deal_id=deal.deal_id,
            command_id=new_ulid(),
            event=DealEvent.CANCELLED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="boundary",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=NOW,
            recorded_at=RECORDED,
        )
        assert store.commit_transition(cancel, make_signer()).outcome is CommitOutcome.COMMITTED

        _, _, events = self._forced_deny(store, deal, approval)
        assert "no longer valid" in events[-1].payload["deny_reason"]
        assert "CANCELLED" in events[-1].payload["deny_reason"]
        assert store.get_deal(deal.deal_id).state is DealState.CANCELLED


class TestCommitTransition:
    def _boundary(self, store, deal, event, **overrides):
        defaults = {
            "deal_id": deal.deal_id,
            "command_id": new_ulid(),
            "event": event,
            "actor_kind": ActorKind.SYSTEM,
            "actor_id": "boundary",
            "authority_record_id": None,
            "amount_minor": None,
            "occurred_at": NOW,
            "recorded_at": RECORDED,
        }
        defaults.update(overrides)
        return TransitionRequest(**defaults)

    def test_boundary_event_applies(self):
        store, deal, signer = _setup(state=DealState.QUOTE_REQUESTED)
        result = store.commit_transition(
            self._boundary(store, deal, DealEvent.QUOTE_RECEIVED), signer
        )
        assert result.outcome is CommitOutcome.COMMITTED
        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.QUOTE_RECEIVED
        events = store.events_for(deal.deal_id)
        assert len(events) == 1
        assert events[0].payload["command_id"]
        assert events[0].payload["from_state"] == "QUOTE_REQUESTED"
        assert events[0].payload["to_state"] == "QUOTE_RECEIVED"

    def test_command_id_makes_retries_noop(self):
        store, deal, signer = _setup(state=DealState.QUOTE_REQUESTED)
        req = self._boundary(store, deal, DealEvent.QUOTE_RECEIVED)
        first = store.commit_transition(req, signer)
        assert first.outcome is CommitOutcome.COMMITTED
        second = store.commit_transition(req, signer)
        assert second.outcome is CommitOutcome.ALREADY_APPLIED
        assert len(store.events_for(deal.deal_id)) == 1
        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.QUOTE_RECEIVED

    def test_stale_boundary_event_aborts(self):
        store, deal, signer = _setup(state=DealState.DRAFT)
        result = store.commit_transition(
            self._boundary(store, deal, DealEvent.QUOTE_RECEIVED), signer
        )
        assert result.outcome is CommitOutcome.STALE_STATE
        assert store.events_for(deal.deal_id) == ()

    def test_deal_not_found(self):
        store, _, signer = _setup()
        other = make_deal(state=DealState.QUOTE_REQUESTED, deal_id=new_ulid())
        result = store.commit_transition(
            self._boundary(store, other, DealEvent.QUOTE_RECEIVED), signer
        )
        assert result.outcome is CommitOutcome.DEAL_NOT_FOUND

    def test_refund_closes_disputes(self):
        store, deal, signer = _setup(state=DealState.DISPUTED, open_disputes=2)
        result = store.commit_transition(self._boundary(store, deal, DealEvent.REFUNDED), signer)
        assert result.outcome is CommitOutcome.COMMITTED
        new_deal = store.get_deal(deal.deal_id)
        assert new_deal is not None
        assert new_deal.state is DealState.REFUNDED
        assert new_deal.open_disputes == 0


class TestEventsFor:
    def test_returns_copy(self):
        store, deal, signer = _setup()
        process_request(_input_for(deal), store, signer, recorded_at=RECORDED)
        events = store.events_for(deal.deal_id)
        assert isinstance(events, tuple)
        assert len(events) == 2

    def test_unknown_deal_is_empty(self):
        store, _, _ = _setup()
        assert store.events_for(new_ulid()) == ()
