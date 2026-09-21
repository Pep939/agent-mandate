"""Receipt forgery against the counterparty (Phase 6, ADR-0012).

Threat: the authority's receipt is the only signal the counterparty's agent
gets about the outcome of its proposal. If the counterparty trusts that
receipt without verifying, a forged, tampered, or replayed receipt can fake
an allow/deny (threat-walkthrough Phase-6 row). The production path under
test is `verify_receipt` — signature against the registered authority
identity, `responds_to` binding to our own `message_id`, freshness window.
`scripts/two_gateways.py` runs exactly this on every response before reading
the outcome.

Two real gateways on separate 127.0.0.1 ports over real HTTP (same shape as
`test_two_gateways.py`'s pair; self-contained here per the adversarial-suite
convention). Every attack must be rejected by the counterparty's verify path
— a forged receipt is never trusted.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn

from mandate.crypto.canonicalization import record_signing_payload
from mandate.crypto.signing import ALGORITHM, GatewaySigner, generate_keypair
from mandate.domain.authority import ActionToken, AuthorityRecord, SignatureBlock, SpendCap
from mandate.domain.deals import Deal, DealState
from mandate.ledger.store import InMemoryLedgerStore
from mandate.transport.dedup import InMemoryWireDedup
from mandate.transport.envelope import (
    CounterpartyEventPayload,
    EnvelopeError,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
    ReceiptOutcome,
    ReceiptPayload,
    WireEnvelope,
    make_envelope,
    verify_receipt,
)
from mandate.transport.gateway import (
    GatewayState,
    build_gateway_state,
    create_gateway_app,
    new_ulid,
    now_iso,
    register_deal,
)


def _make_identity() -> GatewayIdentity:
    private_key, public_key = generate_keypair()
    return GatewayIdentity(identity_id=new_ulid(), public_key=public_key, private_key=private_key)


def _make_signer() -> GatewaySigner:
    private_key, public_key = generate_keypair()
    return GatewaySigner(key_id=new_ulid(), private_key=private_key, public_key=public_key)


def _sign_record(signer: GatewaySigner, *, counterparty_id: str, agent_id: str) -> AuthorityRecord:
    now = now_iso()
    unsigned = AuthorityRecord(
        schema_version="0.1",
        record_id=new_ulid(),
        principal_id=new_ulid(),
        agent_id=agent_id,
        counterparty_id=counterparty_id,
        purpose="receipt-tamper mandate",
        allowed_actions=[a.value for a in ActionToken],
        prohibited_actions=[],
        spend_cap=SpendCap(currency="USD", amount_minor=1_000_000),
        max_negotiation_rounds=10,
        acceptance_window_hours=48,
        silent_acceptance=False,
        disclosure_fields=[],
        requires_human_approval_for=["capture_payment"],
        issued_at=now,
        not_before=now,
        expires_at="2027-01-01T00:00:00+00:00",
        parent_record_id=None,
        status="active",
        nonce=new_ulid(),
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=""),
    )
    value = signer.sign_bytes(record_signing_payload(unsigned))
    return unsigned.model_copy(
        update={"signature": SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=value)}
    )


@dataclass
class Gateway:
    state: GatewayState
    base_url: str
    server: object
    thread: threading.Thread
    client: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=10))

    def post(self, env: WireEnvelope) -> httpx.Response:
        return self.client.post(f"{self.base_url}/messages", content=env.model_dump_json())


@dataclass
class Pair:
    authority: Gateway
    counterparty: Gateway
    deal_id: str
    record: AuthorityRecord


def _start(state: GatewayState) -> Gateway:
    app = create_gateway_app(state)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            msg = "uvicorn did not start within 10s"
            raise RuntimeError(msg)
        time.sleep(0.01)
    sock = server.servers[0].sockets[0]
    return Gateway(
        state=state,
        base_url=f"http://127.0.0.1:{sock.getsockname()[1]}",
        server=server,
        thread=thread,
    )


@pytest.fixture
def pair() -> Iterator[Pair]:
    authority_state = build_gateway_state(
        identity=_make_identity(),
        signer=_make_signer(),
        store=InMemoryLedgerStore(),
        dedup=InMemoryWireDedup(),
    )
    counterparty_state = build_gateway_state(
        identity=_make_identity(),
        signer=_make_signer(),
        store=InMemoryLedgerStore(),
        dedup=InMemoryWireDedup(),
    )
    authority_state.peers[counterparty_state.identity.identity_id] = counterparty_state.identity
    counterparty_state.peers[authority_state.identity.identity_id] = authority_state.identity

    deal_id = new_ulid()
    record = _sign_record(
        authority_state.signer,
        counterparty_id=counterparty_state.identity.identity_id,
        agent_id=counterparty_state.identity.identity_id,
    )
    now = now_iso()
    register_deal(authority_state, deal_id, record, now)
    counterparty_state.store.create_deal(Deal(deal_id=deal_id, state=DealState.DRAFT), now)
    counterparty_state.deal_ids.append(deal_id)

    authority = _start(authority_state)
    counterparty = _start(counterparty_state)
    try:
        yield Pair(authority=authority, counterparty=counterparty, deal_id=deal_id, record=record)
    finally:
        for gw in (authority, counterparty):
            gw.client.close()
            gw.server.should_exit = True  # type: ignore[attr-defined]
            gw.thread.join(timeout=5)


def _proposal(pair: Pair, *, action: str, amount: int | None = None) -> WireEnvelope:
    cp = pair.counterparty.state
    key = new_ulid()
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action=action,
            deal_id=pair.deal_id,
            amount_minor=amount,
            currency=pair.record.spend_cap.currency,
            disclosure_fields=[],
            idempotency_key=key,
        ),
        sender=cp.identity,
        recipient_id=pair.authority.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=key,
        issued_at=now_iso(),
    )


def _counterparty_event(pair: Pair, *, event: str) -> WireEnvelope:
    cp = pair.counterparty.state
    return make_envelope(
        kind=MessageKind.COUNTERPARTY_EVENT,
        payload=CounterpartyEventPayload(deal_id=pair.deal_id, event=event, note=""),
        sender=cp.identity,
        recipient_id=pair.authority.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )


def _receipt_from(response: httpx.Response) -> WireEnvelope:
    """Extract the receipt from a gateway response, as the counterparty does."""
    return WireEnvelope.model_validate(response.json()["receipt"])


def _counterparty_verify(
    pair: Pair, receipt: WireEnvelope, *, expected_responds_to: str
) -> ReceiptPayload:
    """The counterparty's production verify path: the registered authority
    identity, our own message id, the live clock, a 300 s freshness window."""
    authority_identity = pair.counterparty.state.peers[pair.authority.state.identity.identity_id]
    return verify_receipt(
        receipt,
        authority_identity,
        expected_responds_to=expected_responds_to,
        now=now_iso(),
        max_age_seconds=300,
    )


def test_genuine_receipt_verifies_on_the_counterparty_side(pair: Pair) -> None:
    m = _proposal(pair, action="request_quote")
    r = pair.authority.post(m)
    assert r.status_code == 200, r.text
    payload = _counterparty_verify(pair, _receipt_from(r), expected_responds_to=m.message_id)
    assert payload.outcome is ReceiptOutcome.ACCEPTED
    assert payload.decision is not None
    assert payload.decision["outcome"] == "allow"


def test_attacker_forged_receipt_is_rejected(pair: Pair) -> None:
    """An unregistered attacker signs an 'accepted' receipt for our message."""
    m = _proposal(pair, action="request_quote")
    r = pair.authority.post(m)
    assert r.status_code == 200, r.text
    forged = make_envelope(
        kind=MessageKind.RECEIPT,
        payload=ReceiptPayload(
            responds_to=m.message_id, outcome=ReceiptOutcome.ACCEPTED, status=200
        ),
        sender=_make_identity(),
        recipient_id=pair.counterparty.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )
    with pytest.raises(EnvelopeError, match="does not match registered peer"):
        _counterparty_verify(pair, forged, expected_responds_to=m.message_id)


def test_tampered_genuine_receipt_is_rejected(pair: Pair) -> None:
    """A genuine receipt with the outcome flipped after signing."""
    m = _proposal(pair, action="request_quote")
    r = pair.authority.post(m)
    assert r.status_code == 200, r.text
    receipt = _receipt_from(r)
    tampered_payload = {**receipt.payload, "outcome": "rejected"}
    tampered = receipt.model_copy(update={"payload": tampered_payload})
    with pytest.raises(EnvelopeError, match="signature"):
        _counterparty_verify(pair, tampered, expected_responds_to=m.message_id)


def test_replayed_receipt_for_different_message_rejected(pair: Pair) -> None:
    """A genuine receipt answering message 1 is not an answer to message 3."""
    m1 = _proposal(pair, action="request_quote")
    r1 = pair.authority.post(m1)
    assert r1.status_code == 200, r1.text
    receipt1 = _receipt_from(r1)

    m2 = _counterparty_event(pair, event="quote_received")
    assert pair.authority.post(m2).status_code == 200

    m3 = _proposal(pair, action="accept_agreement", amount=250_000)
    r3 = pair.authority.post(m3)
    assert r3.status_code == 200, r3.text

    with pytest.raises(EnvelopeError, match="not an answer to this message"):
        _counterparty_verify(pair, receipt1, expected_responds_to=m3.message_id)
    # And the genuine answer to message 3 verifies clean.
    payload = _counterparty_verify(pair, _receipt_from(r3), expected_responds_to=m3.message_id)
    assert payload.decision is not None


def test_stale_receipt_is_rejected(pair: Pair) -> None:
    """Genuine authority signature, real message id, but issued_at outside the
    window (broken clock or a captured old receipt) — not a live answer."""
    m = _proposal(pair, action="request_quote")
    r = pair.authority.post(m)
    assert r.status_code == 200, r.text
    stale_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    stale = make_envelope(
        kind=MessageKind.RECEIPT,
        payload=ReceiptPayload(
            responds_to=m.message_id, outcome=ReceiptOutcome.ACCEPTED, status=200
        ),
        sender=pair.authority.state.identity,
        recipient_id=pair.counterparty.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=stale_time,
    )
    with pytest.raises(EnvelopeError, match="stale"):
        _counterparty_verify(pair, stale, expected_responds_to=m.message_id)
