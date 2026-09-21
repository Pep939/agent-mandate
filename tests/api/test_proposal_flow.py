"""End-to-end operator flows through the console (ADR-0011).

Covers the claim surface: propose → decision, approval grant/deny, revocation,
boundary transition, and the replay-gate render. Each flow drives the real
single writer path (process_request / commit_*), so these also exercise that
the boundary claim is verified (signature + revocation) before evaluation.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from mandate.api import boundary
from mandate.api.state import AppState
from mandate.crypto.signing import GatewaySigner, generate_keypair
from mandate.domain.authority import ActionToken
from mandate.ledger.store import ApprovalStatus, InMemoryLedgerStore
from tests.api.conftest import PASSWORD
from tests.api.support import csrf_token, first_approval_id, first_deal_id

EXPIRES = "2027-01-01T00:00:00+00:00"


def _propose(c: TestClient, deal_id: str, action: str, amount: str | None = None) -> str:
    html = c.get(f"/deals/{deal_id}/propose").text
    data = {"action": action, "csrf_token": csrf_token(html)}
    if amount is not None:
        data["amount_dollars"] = amount
    return c.post(f"/deals/{deal_id}/propose", data=data).text


def _custom_state(approval_actions: list[str]) -> AppState:
    store = InMemoryLedgerStore()
    private_key, public_key = generate_keypair()
    signer = GatewaySigner(
        key_id=boundary.new_ulid(), private_key=private_key, public_key=public_key
    )
    state = AppState(
        store=store,
        signer=signer,
        operator_id="operator",
        operator_password=PASSWORD,
        session_secret="ss",
    )
    now = boundary.now_iso()
    deal_id = boundary.new_ulid()
    record = boundary.make_signed_record(
        state,
        now=now,
        agent_id=boundary.new_ulid(),
        principal_id=boundary.new_ulid(),
        purpose="custom",
        allowed_actions=[a.value for a in ActionToken],
        spend_cap_currency="USD",
        spend_cap_minor=1_000_000,
        max_negotiation_rounds=10,
        expires_at=EXPIRES,
        requires_human_approval_for=list(approval_actions),
    )
    boundary.register_deal(state, deal_id, record, now)
    state.deal_ids.append(deal_id)  # ensure listed
    return state


def test_propose_allows_and_advances_state(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    html = _propose(client, deal_id, "request_quote")
    assert "Allowed" in html
    assert "QUOTE_REQUESTED" in html
    # the deal row reflects the new state
    assert client.get(f"/deals/{deal_id}").text.count("QUOTE_REQUESTED") >= 1


def test_propose_unknown_action_is_rejected(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    html = client.get(f"/deals/{deal_id}/propose").text
    response = client.post(
        f"/deals/{deal_id}/propose",
        data={"action": "self_destruct", "csrf_token": csrf_token(html)},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_propose_invalid_amount_is_rejected(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    html = client.get(f"/deals/{deal_id}/propose").text
    response = client.post(
        f"/deals/{deal_id}/propose",
        data={
            "action": "accept_agreement",
            "amount_dollars": "not-a-number",
            "csrf_token": csrf_token(html),
        },
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_propose_negative_amount_is_rejected(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    html = client.get(f"/deals/{deal_id}/propose").text
    response = client.post(
        f"/deals/{deal_id}/propose",
        data={
            "action": "accept_agreement",
            "amount_dollars": "-500",
            "csrf_token": csrf_token(html),
        },
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_approval_grant_advances_state(fresh_client):
    state = _custom_state(["request_quote"])
    c = fresh_client(state)
    deal_id = first_deal_id(c.get("/").text)
    html = _propose(c, deal_id, "request_quote")
    assert "Needs a person" in html  # approval required
    # approval appears on the deal page
    deal_html = c.get(f"/deals/{deal_id}").text
    approval_id = first_approval_id(deal_html)
    token = csrf_token(deal_html)
    c.post(
        f"/deals/{deal_id}/approvals/{approval_id}/decision",
        data={"operation": "granted", "csrf_token": token},
        follow_redirects=False,
    )
    after = c.get(f"/deals/{deal_id}").text
    assert "QUOTE_REQUESTED" in after
    # the approval is now granted, not pending
    pending = [a for a in state.store.approvals_for(deal_id) if a.status is ApprovalStatus.PENDING]
    assert pending == []


def test_approval_deny_keeps_state(fresh_client):
    state = _custom_state(["request_quote"])
    c = fresh_client(state)
    deal_id = first_deal_id(c.get("/").text)
    _propose(c, deal_id, "request_quote")
    deal_html = c.get(f"/deals/{deal_id}").text
    approval_id = first_approval_id(deal_html)
    c.post(
        f"/deals/{deal_id}/approvals/{approval_id}/decision",
        data={"operation": "denied", "deny_reason": "not now", "csrf_token": csrf_token(deal_html)},
        follow_redirects=False,
    )
    after = c.get(f"/deals/{deal_id}").text
    assert "DRAFT" in after  # state did not advance
    approval = state.store.get_approval(approval_id)
    assert approval is not None and approval.status is ApprovalStatus.DENIED
    assert approval.decided_by == "operator"


def test_revoke_then_propose_is_denied(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    token = csrf_token(client.get(f"/deals/{deal_id}").text)
    client.post(f"/deals/{deal_id}/revoke", data={"csrf_token": token}, follow_redirects=False)
    html = _propose(client, deal_id, "request_quote")
    assert "Denied" in html
    assert "revoked" in html.lower()


def test_boundary_event_advances_and_invalid_is_reported(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    token = csrf_token(client.get(f"/deals/{deal_id}").text)
    # invalid from DRAFT: payment_confirmed is not a valid transition
    bad = client.post(
        f"/deals/{deal_id}/boundary", data={"event": "payment_confirmed", "csrf_token": token}
    )
    assert "Not applied" in bad.text
    # advance to QUOTE_REQUESTED, then record the (valid) quote_received boundary event
    _propose(client, deal_id, "request_quote")
    token2 = csrf_token(client.get(f"/deals/{deal_id}").text)
    good = client.post(
        f"/deals/{deal_id}/boundary", data={"event": "quote_received", "csrf_token": token2}
    )
    assert "Recorded" in good.text
    assert "QUOTE_RECEIVED" in good.text


def test_timeline_lists_events_after_activity(client: TestClient):
    deal_id = first_deal_id(client.get("/").text)
    _propose(client, deal_id, "request_quote")
    timeline = client.get(f"/deals/{deal_id}/timeline").text
    assert "policy_decision" in timeline
    assert "state_transition" in timeline


def test_new_deal_is_listed_and_usable(client: TestClient):
    before = len(client.app.state.mandate.deal_ids)
    token = csrf_token(client.get("/").text)
    client.post("/deals/new", data={"csrf_token": token}, follow_redirects=False)
    state = client.app.state.mandate
    assert len(state.deal_ids) == before + 1
    new_id = state.deal_ids[-1]
    # the new deal is usable: it has a mandate and accepts a proposal
    html = _propose(client, new_id, "request_quote")
    assert "Allowed" in html


def test_deny_reason_html_is_escaped_in_timeline(fresh_client):
    """A hostile deny_reason (operator/counterparty text) must render escaped,
    not as live markup, in the timeline (invariant 11)."""
    state = _custom_state(["request_quote"])
    c = fresh_client(state)
    deal_id = first_deal_id(c.get("/").text)
    _propose(c, deal_id, "request_quote")
    deal_html = c.get(f"/deals/{deal_id}").text
    approval_id = first_approval_id(deal_html)
    payload = '<script>alert("xss")</script>'
    c.post(
        f"/deals/{deal_id}/approvals/{approval_id}/decision",
        data={"operation": "denied", "deny_reason": payload, "csrf_token": csrf_token(deal_html)},
        follow_redirects=False,
    )
    timeline = c.get(f"/deals/{deal_id}/timeline").text
    assert "<script>" not in timeline
    assert "&lt;script&gt;" in timeline
