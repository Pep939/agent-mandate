"""Approve-vs-revoke race (Phase 5: threat-walkthrough "true parallel races").

A grant and a revocation hit the live server at the same instant. Either
landing order is legal — but the ledger must end in exactly one consistent
state (invariants 3, 7, 14): the transition either applied under a mandate
that was still current at decision time (ADR-0010 step 2), or the grant
became a logged deny because the revocation won the recheck.
"""

from __future__ import annotations

import threading

from mandate.domain.approvals import ApprovalStatus
from mandate.domain.deals import DealState
from mandate.domain.decisions import ReasonCode
from mandate.domain.events import EventType
from mandate.ledger.chain import verify_chain
from tests.adversarial.agents import Agent, mandate_kwargs, run_to_open_capture_approval
from tests.adversarial.conftest import PASSWORD


def test_grant_revoke_race(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    principal = Agent(live_server.base_url, PASSWORD, "principal")
    revoker = Agent(live_server.base_url, PASSWORD, "revoker")
    provider = Agent(live_server.base_url, PASSWORD, "provider")
    try:
        aid = run_to_open_capture_approval(provider, revoker, deal_id)

        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def grant_it() -> None:
            try:
                barrier.wait(timeout=10)
                principal.grant(deal_id, aid)
            except BaseException as exc:
                errors.append(exc)

        def revoke_it() -> None:
            try:
                barrier.wait(timeout=10)
                revoker.revoke(deal_id)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=grant_it), threading.Thread(target=revoke_it)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, errors

        approval = live_server.state.store.get_approval(aid)
        deal = live_server.state.store.get_deal(deal_id)
        assert approval is not None
        assert deal is not None
        assert approval.status in (ApprovalStatus.GRANTED, ApprovalStatus.DENIED)
        assert deal.open_approvals == 0

        events = live_server.state.store.events_for(deal_id)
        if approval.status is ApprovalStatus.GRANTED:
            # the grant's recheck saw a current mandate: the transition
            # applied; a later revocation only affects future proposals
            assert deal.state is DealState.CAPTURED
        else:
            # the revocation won the recheck: the grant became a logged deny
            # that closed the approval (ADR-0010 step 2, invariant 7)
            assert deal.state is DealState.PAYMENT_PENDING
            denied = [
                e
                for e in events
                if e.event_type is EventType.APPROVAL and e.payload.get("operation") == "denied"
            ]
            assert len(denied) == 1
            assert "no longer current" in denied[0].payload["deny_reason"]
            # and the mandate is dead for any future proposal
            d = provider.propose(deal_id, "capture_payment")
            assert d.outcome == "Denied"
            assert d.reason_code is ReasonCode.RECORD_REVOKED

        # whichever order won, the evidence trail is intact and verifies
        report = verify_chain(events, live_server.state.signer.public_key)
        assert report.ok, report.first_failure()
    finally:
        principal.close()
        revoker.close()
        provider.close()
