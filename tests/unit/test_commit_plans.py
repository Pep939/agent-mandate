"""Unit tests for the pure commit plans (C3).

The plans are the single code path for what a commit appends — both ledger
backends persist exactly what these functions return, so the contract
pinned here is: purity (same inputs, identical bytes), shape (which events,
which deal/approval projections), and chain validity (planned events verify
under `verify_chain` the way the stored chain must).
"""

from __future__ import annotations

from mandate.domain.approvals import Approval, ApprovalStatus
from mandate.domain.authority import ActionToken, Revocation, SignatureBlock
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.decisions import Outcome, PolicyDecision, ReasonCode
from mandate.domain.events import EventType
from mandate.domain.input import ActorKind
from mandate.ledger.chain import verify_chain
from mandate.ledger.commit_plans import (
    ApprovalDecision,
    plan_commit_approval,
    plan_commit_request,
    plan_commit_revocation,
    plan_commit_transition,
)
from mandate.ledger.store import (
    ApprovalRequest,
    CommitRequest,
    RevocationRequest,
    TransitionRequest,
)
from tests.support.factories import (
    NOW,
    make_deal,
    make_proposal,
    make_record,
    make_signer,
    new_ulid,
)

RECORDED = "2026-01-15T12:00:01Z"
GENESIS = "0" * 64


def _decision(outcome: Outcome, reason: ReasonCode, record) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,
        reason_code=reason,
        explanation="unit test decision",
        matched_rule="test",
        authority_record_id=record.record_id,
        evaluated_at=NOW,
        input_digest=GENESIS,
    )


def _request(deal, decision: PolicyDecision, record, **overrides):
    prop = make_proposal(deal_id=deal.deal_id, **overrides)
    return CommitRequest(
        deal_id=deal.deal_id,
        request_id=new_ulid(),
        decision=decision,
        actor_kind=ActorKind.AGENT,
        actor_id=record.agent_id,
        authority_record_id=record.record_id,
        action=prop.action,
        amount_minor=prop.amount_minor,
        occurred_at=NOW,
        recorded_at=RECORDED,
        idempotency_key=prop.idempotency_key,
        proposal_digest=GENESIS,
        record=record,
    )


class TestRequestPlan:
    def test_allow_appends_decision_then_transition(self):
        deal = make_deal(state=DealState.DRAFT)
        record = make_record()
        req = _request(deal, _decision(Outcome.ALLOW, ReasonCode.OK, record), record)
        signer = make_signer()

        plan = plan_commit_request(deal, 3, GENESIS, req, DealEvent.QUOTE_REQUESTED, signer)

        assert [e.event_type for e in plan.events] == [
            EventType.POLICY_DECISION,
            EventType.STATE_TRANSITION,
        ]
        assert [e.sequence_number for e in plan.events] == [3, 4]
        assert plan.events[1].previous_event_hash == plan.events[0].event_hash
        assert plan.new_deal.state is DealState.QUOTE_REQUESTED
        assert plan.approval is None

    def test_deny_appends_decision_only(self):
        deal = make_deal(state=DealState.DRAFT)
        record = make_record()
        req = _request(deal, _decision(Outcome.DENY, ReasonCode.RECORD_REVOKED, record), record)
        signer = make_signer()

        plan = plan_commit_request(deal, 1, GENESIS, req, None, signer)

        assert [e.event_type for e in plan.events] == [EventType.POLICY_DECISION]
        assert plan.events[0].sequence_number == 1
        assert plan.events[0].previous_event_hash == GENESIS
        assert plan.new_deal == deal
        assert plan.approval is None

    def test_needs_approval_opens_pending_approval(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        record = make_record()
        req = _request(
            deal,
            _decision(Outcome.NEEDS_APPROVAL, ReasonCode.APPROVAL_REQUIRED, record),
            record,
            action="accept_agreement",
            amount_minor=10**9,
        )
        signer = make_signer()

        plan = plan_commit_request(deal, 5, GENESIS, req, None, signer)

        assert [e.event_type for e in plan.events] == [
            EventType.POLICY_DECISION,
            EventType.APPROVAL,
        ]
        assert plan.approval is not None
        assert plan.approval.status is ApprovalStatus.PENDING
        assert plan.approval.action == "accept_agreement"
        assert plan.approval.amount_minor == 10**9
        assert plan.new_deal == deal.model_copy(update={"open_approvals": 1})

    def test_same_inputs_give_identical_policy_content(self):
        """Policy content is deterministic; the event_id is a uniqueness
        nonce (80 random bits) and may differ call to call."""
        deal = make_deal(state=DealState.DRAFT)
        record = make_record()
        signer = make_signer()
        req = _request(deal, _decision(Outcome.ALLOW, ReasonCode.OK, record), record)

        a = plan_commit_request(deal, 0, GENESIS, req, DealEvent.QUOTE_REQUESTED, signer)
        b = plan_commit_request(deal, 0, GENESIS, req, DealEvent.QUOTE_REQUESTED, signer)

        assert len(a.events) == len(b.events)
        for ea, eb in zip(a.events, b.events, strict=True):
            assert ea.event_type == eb.event_type
            assert ea.sequence_number == eb.sequence_number
            assert ea.payload == eb.payload
            assert ea.payload_hash == eb.payload_hash
            assert ea.event_id != eb.event_id  # the nonce keeps ids unique
        assert a.new_deal == b.new_deal


class TestTransitionPlan:
    def test_single_transition_event_and_new_state(self):
        deal = make_deal(state=DealState.QUOTE_REQUESTED)
        req = TransitionRequest(
            deal_id=deal.deal_id,
            command_id=new_ulid(),
            event=DealEvent.QUOTE_RECEIVED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="unit-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=NOW,
            recorded_at=RECORDED,
        )

        plan = plan_commit_transition(
            deal, 2, GENESIS, req, DealState.QUOTE_RECEIVED, make_signer()
        )

        assert [e.event_type for e in plan.events] == [EventType.STATE_TRANSITION]
        assert plan.events[0].sequence_number == 2
        assert plan.events[0].previous_event_hash == GENESIS
        assert plan.new_deal.state is DealState.QUOTE_RECEIVED
        assert plan.approval is None


class TestApprovalPlan:
    def _pending(self, deal):
        record = make_record()
        approval = Approval(
            approval_id=new_ulid(),
            deal_id=deal.deal_id,
            request_id=new_ulid(),
            authority_record_id=record.record_id,
            action="accept_agreement",
            amount_minor=10**9,
            currency="USD",
            proposal_digest=GENESIS,
            reason_code=ReasonCode.APPROVAL_REQUIRED,
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_at=None,
            command_id=None,
            created_at=NOW,
        )
        return record, approval

    def _grant_req(self, deal, approval, **overrides):
        from mandate.crypto.signing import make_approval_record

        defaults = {
            "deal_id": deal.deal_id,
            "approval_id": approval.approval_id,
            "command_id": new_ulid(),
            "operation": ApprovalDecision.GRANTED,
            "actor_kind": ActorKind.PRINCIPAL,
            "actor_id": new_ulid(),
            "authority_record_id": approval.authority_record_id,
            "action": approval.action,
            "amount_minor": approval.amount_minor,
            "occurred_at": NOW,
            "recorded_at": RECORDED,
            "decided_by": approval.authority_record_id,
            "approval_record": make_approval_record(
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
            ),
        }
        defaults.update(overrides)
        return ApprovalRequest(**defaults)

    def test_grant_applies_transition_and_closes_approval(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED, open_approvals=1)
        record, approval = self._pending(deal)
        req = self._grant_req(deal, approval)

        plan = plan_commit_approval(
            deal,
            approval,
            4,
            GENESIS,
            req,
            record,
            False,
            ActionToken.ACCEPT_AGREEMENT,
            make_signer(),
        )

        assert [e.event_type for e in plan.events] == [
            EventType.APPROVAL,
            EventType.STATE_TRANSITION,
        ]
        assert plan.events[1].previous_event_hash == plan.events[0].event_hash
        assert plan.new_deal.state is DealState.AGREED
        assert plan.new_deal.open_approvals == 0
        assert plan.approval is not None
        assert plan.approval.status is ApprovalStatus.GRANTED
        assert plan.approval.command_id == req.command_id

    def test_grant_with_revoked_parent_is_forced_deny(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED, open_approvals=1)
        record, approval = self._pending(deal)
        req = self._grant_req(deal, approval)

        plan = plan_commit_approval(
            deal,
            approval,
            4,
            GENESIS,
            req,
            record,
            True,
            ActionToken.ACCEPT_AGREEMENT,
            make_signer(),
        )

        assert [e.event_type for e in plan.events] == [EventType.APPROVAL]
        assert plan.new_deal == deal.model_copy(update={"open_approvals": 0})
        assert plan.approval is not None
        assert plan.approval.status is ApprovalStatus.DENIED

    def test_operator_deny_closes_without_transition(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED, open_approvals=1)
        _, approval = self._pending(deal)
        req = self._grant_req(
            deal,
            approval,
            operation=ApprovalDecision.DENIED,
            approval_record=None,
            deny_reason="out of scope",
        )

        plan = plan_commit_approval(
            deal, approval, 4, GENESIS, req, None, False, None, make_signer()
        )

        assert [e.event_type for e in plan.events] == [EventType.APPROVAL]
        assert plan.new_deal == deal.model_copy(update={"open_approvals": 0})
        assert plan.approval is not None
        assert plan.approval.status is ApprovalStatus.DENIED


class TestRevocationPlan:
    def test_single_event_deal_unchanged(self):
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        signer = make_signer()
        req = RevocationRequest(
            deal_id=deal.deal_id,
            revocation=Revocation(
                schema_version="0.1",
                revocation_id=new_ulid(),
                record_id=new_ulid(),
                revoked_at=NOW,
                signature=SignatureBlock(algorithm="ed25519", key_id="unit-test", value="sig"),
            ),
            command_id=new_ulid(),
            actor_kind=ActorKind.PRINCIPAL,
            actor_id=new_ulid(),
            occurred_at=NOW,
            recorded_at=RECORDED,
        )

        plan = plan_commit_revocation(deal, 6, GENESIS, req, signer)

        assert [e.event_type for e in plan.events] == [EventType.REVOCATION]
        assert plan.events[0].sequence_number == 6
        assert plan.new_deal == deal


class TestPlanChainsVerify:
    def test_planned_events_form_a_verifying_chain(self):
        """The events the backends persist, in plan order, must verify."""
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        record = make_record()

        req = _request(deal, _decision(Outcome.ALLOW, ReasonCode.OK, record), record)
        p1 = plan_commit_request(deal, 0, GENESIS, req, DealEvent.QUOTE_REQUESTED, signer)
        assert len(p1.events) == 2

        head = p1.new_deal
        seq = 2  # the request plan consumed 0 and 1
        prev = p1.events[-1].event_hash
        transition = TransitionRequest(
            deal_id=head.deal_id,
            command_id=new_ulid(),
            event=DealEvent.QUOTE_RECEIVED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="unit-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=NOW,
            recorded_at=RECORDED,
        )
        p2 = plan_commit_transition(head, seq, prev, transition, DealState.QUOTE_RECEIVED, signer)

        assert verify_chain((*p1.events, *p2.events), signer.public_key).ok
