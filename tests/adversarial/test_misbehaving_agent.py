"""A provider that keeps trying to push past its mandate, over real HTTP.

Each test registers a deal under a specific signed mandate, lets the agent
misbehave, and asserts the exact machine reason the engine returned —
recovered from the rendered plain-language sentence, so the assertion is on
the decision, not on the phrasing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mandate.domain.authority import ActionToken
from mandate.domain.decisions import ReasonCode
from tests.adversarial.agents import Agent, mandate_kwargs
from tests.adversarial.conftest import LiveServer


def _agent(server: LiveServer, name: str = "provider") -> Agent:
    return Agent(server.base_url, server.password, name)


def _to_quote_received(server: LiveServer, provider: Agent, **mandate_overrides: object) -> str:
    """Register a mandate deal (with overrides) and move it to QUOTE_RECEIVED.

    Returns the deal_id — callers must use it, the deal is what was driven.
    """
    customer = Agent(server.base_url, server.password, "customer")
    deal_id = server.register_deal(**mandate_kwargs(**mandate_overrides))
    assert provider.propose(deal_id, "request_quote").state == "QUOTE_REQUESTED"
    assert customer.boundary(deal_id, "quote_received").state == "QUOTE_RECEIVED"
    customer.close()
    return deal_id


def test_action_not_allowed(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs(allowed_actions=["request_quote"]))
    with _agent(live_server) as provider:
        d = provider.propose(deal_id, "accept_agreement", "100")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.ACTION_NOT_ALLOWED


def test_prohibition_beats_allowance(live_server):
    with _agent(live_server) as provider:
        deal_id = _to_quote_received(
            live_server,
            provider,
            prohibited_actions=[ActionToken.ACCEPT_AGREEMENT.value],
        )
        d = provider.propose(deal_id, "accept_agreement", "100")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.ACTION_PROHIBITED


def test_spend_cap_escalates_to_approval(live_server):
    with _agent(live_server) as provider:
        deal_id = _to_quote_received(live_server, provider, spend_cap_minor=100_000)
        d = provider.propose(deal_id, "accept_agreement", "2,500")
        assert d.outcome == "Needs a person's approval"
        assert d.reason_code is ReasonCode.SPEND_CAP_EXCEEDED
        # the deal did not move: escalation is not authorization
        assert d.state == "QUOTE_RECEIVED"


def test_cumulative_cap_includes_change_orders(live_server):
    # $1,000 cap: a $600 agreement fits, a $500 change order would push the
    # deal to $1,100 (invariant 8: cumulative across the whole deal)
    deal_id = live_server.register_deal(**mandate_kwargs(spend_cap_minor=100_000))
    customer = Agent(live_server.base_url, live_server.password, "customer")
    with _agent(live_server) as provider, customer:
        assert provider.propose(deal_id, "request_quote").state == "QUOTE_REQUESTED"
        assert customer.boundary(deal_id, "quote_received").state == "QUOTE_RECEIVED"
        assert provider.propose(deal_id, "accept_agreement", "600").state == "AGREED"
        assert provider.propose(deal_id, "start_work").state == "IN_PROGRESS"
        d = provider.propose(deal_id, "propose_change", "500")
        assert d.outcome == "Needs a person's approval"
        assert d.reason_code is ReasonCode.SPEND_CAP_EXCEEDED


def test_invalid_state_denied(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with _agent(live_server) as provider:
        assert provider.propose(deal_id, "request_quote").state == "QUOTE_REQUESTED"
        d = provider.propose(deal_id, "request_quote")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.INVALID_TRANSITION


def test_revoked_mandate_authorizes_nothing(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with _agent(live_server) as provider, _agent(live_server, "principal") as principal:
        assert provider.propose(deal_id, "request_quote").state == "QUOTE_REQUESTED"
        principal.revoke(deal_id)
        assert provider.view(deal_id).mandate_state == "revoked"
        d = provider.propose(deal_id, "counteroffer", "50")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.RECORD_REVOKED


def test_expired_mandate_authorizes_nothing(live_server):
    yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    deal_id = live_server.register_deal(**mandate_kwargs(expires_at=yesterday))
    with _agent(live_server) as provider:
        d = provider.propose(deal_id, "request_quote")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.RECORD_EXPIRED


def test_tampered_mandate_carries_no_authority(live_server):
    with _agent(live_server) as provider:
        deal_id = _to_quote_received(live_server, provider)
        record = live_server.state.store.get_record(live_server.state.deal_records[deal_id])
        assert record is not None
        inflated = record.model_copy(
            update={"spend_cap": record.spend_cap.model_copy(update={"amount_minor": 10**9})}
        )
        live_server.state.store.put_record(inflated)
        # $50,000 fits the forged cap but not the signed one — and the
        # signature no longer matches the stored bytes at all
        d = provider.propose(deal_id, "accept_agreement", "50,000")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.INVALID_SIGNATURE_CLAIM


def test_negotiation_round_flood(live_server):
    with _agent(live_server) as provider:
        deal_id = _to_quote_received(live_server, provider)
        for _ in range(10):
            d = provider.propose(deal_id, "counteroffer", "100")
            assert d.outcome == "Allowed", (d.outcome, d.sentence)
        d = provider.propose(deal_id, "counteroffer", "100")
        assert d.outcome == "Denied"
        assert d.reason_code is ReasonCode.NEGOTIATION_LIMIT_REACHED


def test_unauthenticated_post_rejected(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    client = httpx.Client(base_url=live_server.base_url, timeout=10)
    try:
        response = client.post(
            f"/deals/{deal_id}/propose", data={"action": "request_quote", "csrf_token": "x"}
        )
        assert response.status_code == 403
    finally:
        client.close()


def test_foreign_csrf_token_rejected(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with _agent(live_server) as provider, _agent(live_server, "other") as other:
        response = provider.client.post(
            f"/deals/{deal_id}/propose",
            data={"action": "request_quote", "csrf_token": other._token()},
        )
        assert response.status_code == 400


def test_unknown_action_rejected(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    with _agent(live_server) as provider, pytest.raises(AssertionError, match="400"):
        provider.propose(deal_id, "launch_missiles")


def test_boundary_rejects_stale_event(live_server):
    deal_id = live_server.register_deal(**mandate_kwargs())
    customer = Agent(live_server.base_url, live_server.password, "customer")
    try:
        d = customer.boundary(deal_id, "work_started")  # not valid from DRAFT
        assert d.outcome == "Not applied"
        assert d.sentence.startswith("stale_state")
    finally:
        customer.close()
