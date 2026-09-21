"""Two simulated agents drive the full deal lifecycle over real HTTP (Phase 5).

The provider proposes actions under its signed mandate; the customer is the
counterparty that records boundary events and, acting as the principal's
delegate, decides the approval. Assertions are on what the console renders
plus the shared runtime state, and every test ends with the whole event
chain independently verifying against the gateway key (brief §13).
"""

from __future__ import annotations

from mandate.domain.decisions import ReasonCode
from mandate.ledger.chain import verify_chain
from tests.adversarial.agents import (
    Agent,
    mandate_kwargs,
    run_to_acceptance_window,
    run_to_open_capture_approval,
)
from tests.adversarial.conftest import PASSWORD


def _assert_chain_ok(server, deal_id: str) -> None:
    events = server.state.store.events_for(deal_id)
    report = verify_chain(events, server.state.signer.public_key)
    assert report.ok, report.first_failure()


def test_full_lifecycle_to_capture(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with (
        Agent(live_server.base_url, PASSWORD, "provider") as provider,
        Agent(live_server.base_url, PASSWORD, "customer") as customer,
    ):
        run_to_open_capture_approval(provider, customer, deal_id)

        view = customer.view(deal_id)
        assert view.state == "PAYMENT_PENDING"
        assert view.committed_minor == 50_000
        customer.grant(deal_id, view.approval_ids[0])

        view = customer.view(deal_id)
        assert view.state == "CAPTURED"
        assert view.approval_ids == ()
        deal = live_server.state.store.get_deal(deal_id)
        assert deal is not None
        assert deal.open_approvals == 0
        _assert_chain_ok(live_server, deal_id)


def test_approval_deny_keeps_deal_waiting(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with (
        Agent(live_server.base_url, PASSWORD, "provider") as provider,
        Agent(live_server.base_url, PASSWORD, "customer") as customer,
    ):
        aid = run_to_open_capture_approval(provider, customer, deal_id)
        customer.deny(deal_id, aid, "over budget this quarter")

        view = customer.view(deal_id)
        assert view.state == "PAYMENT_PENDING"
        assert view.approval_ids == ()

        # a fresh proposal may reopen approval on the same deal
        d = provider.propose(deal_id, "capture_payment")
        assert d.outcome == "Needs a person's approval"
        (aid2,) = customer.view(deal_id).approval_ids
        assert aid2 != aid
        customer.grant(deal_id, aid2)
        assert customer.view(deal_id).state == "CAPTURED"
        _assert_chain_ok(live_server, deal_id)


def test_dispute_flow(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with (
        Agent(live_server.base_url, PASSWORD, "provider") as provider,
        Agent(live_server.base_url, PASSWORD, "customer") as customer,
    ):
        run_to_acceptance_window(provider, customer, deal_id)

        d = customer.boundary(deal_id, "dispute_opened")
        assert d.state == "DISPUTED", (d.outcome, d.sentence)
        deal = live_server.state.store.get_deal(deal_id)
        assert deal is not None
        assert deal.open_disputes == 1

        # no payment capture while the deal is disputed
        d = provider.propose(deal_id, "capture_payment")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.INVALID_TRANSITION

        # the dispute resolves through acceptance and the counter closes
        d = provider.propose(deal_id, "accept_completion")
        assert (d.outcome, d.state) == ("Allowed", "ACCEPTED")
        deal = live_server.state.store.get_deal(deal_id)
        assert deal is not None
        assert deal.open_disputes == 0

        # the deal still closes out end to end
        d = provider.propose(deal_id, "initiate_payment")
        assert d.state == "PAYMENT_PENDING"
        d = provider.propose(deal_id, "capture_payment")
        assert d.outcome == "Needs a person's approval"
        (approval_id,) = customer.view(deal_id).approval_ids
        customer.grant(deal_id, approval_id)
        assert customer.view(deal_id).state == "CAPTURED"
        _assert_chain_ok(live_server, deal_id)


def test_payment_blocked_while_approval_open(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with (
        Agent(live_server.base_url, PASSWORD, "provider") as provider,
        Agent(live_server.base_url, PASSWORD, "customer") as customer,
    ):
        run_to_open_capture_approval(provider, customer, deal_id)

        # invariant 10: no payment action while a required approval is open
        d = provider.propose(deal_id, "capture_payment")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.PAYMENT_BLOCKED_BY_OPEN_APPROVAL

        # closing the approval unblocks the payment
        (approval_id,) = customer.view(deal_id).approval_ids
        customer.grant(deal_id, approval_id)
        assert customer.view(deal_id).state == "CAPTURED"
        _assert_chain_ok(live_server, deal_id)
