"""Two-gateway end-to-end (Phase 6, ADR-0012).

Two real gateways on separate 127.0.0.1 ports, talking over real HTTP. Gateway
A is the authority (it owns the deal's ledger and runs the policy engine);
gateway B is the counterparty (it hosts the agent and originates boundary
events). Every deal hop crosses the wire as a signed, idempotent envelope;
each gateway's ledger independently `verify_chain`s clean (invariant 15).

In-memory stores/dedup keep this in the default (no-database) suite; the
Postgres-backed wire dedup is covered separately in test_postgres.py.
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
from mandate.domain.deals import Deal, DealEvent, DealState
from mandate.domain.input import ActorKind
from mandate.ledger.chain import verify_chain
from mandate.ledger.store import InMemoryLedgerStore, TransitionRequest
from mandate.transport.dedup import InMemoryWireDedup
from mandate.transport.envelope import (
    CounterpartyEventPayload,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
    WireEnvelope,
    make_envelope,
    verify_envelope,
)
from mandate.transport.gateway import (
    GatewayState,
    build_gateway_state,
    create_gateway_app,
    new_ulid,
    now_iso,
    register_deal,
)


def _make_signer() -> GatewaySigner:
    private_key, public_key = generate_keypair()
    return GatewaySigner(key_id=new_ulid(), private_key=private_key, public_key=public_key)


def _make_identity() -> GatewayIdentity:
    private_key, public_key = generate_keypair()
    return GatewayIdentity(identity_id=new_ulid(), public_key=public_key, private_key=private_key)


def sign_record(
    signer: GatewaySigner, *, counterparty_id: str, **overrides: object
) -> AuthorityRecord:
    """A signed, active, audience-restricted mandate, mirroring the console's
    `make_signed_record` but over a bare gateway signer."""
    now = now_iso()
    kwargs: dict[str, object] = {
        "agent_id": new_ulid(),
        "principal_id": new_ulid(),
        "purpose": "two-gateway mandate",
        "allowed_actions": [a.value for a in ActionToken],
        "spend_cap_currency": "USD",
        "spend_cap_minor": 1_000_000,
        "max_negotiation_rounds": 10,
        "expires_at": "2027-01-01T00:00:00+00:00",
        "requires_human_approval_for": ["capture_payment"],
        "counterparty_id": counterparty_id,
    }
    kwargs.update(overrides)
    unsigned = AuthorityRecord(
        schema_version="0.1",
        record_id=new_ulid(),
        principal_id=kwargs["principal_id"],
        agent_id=kwargs["agent_id"],
        counterparty_id=counterparty_id,
        purpose=kwargs["purpose"],
        allowed_actions=list(kwargs["allowed_actions"]),
        prohibited_actions=list(kwargs.get("prohibited_actions") or ()),  # type: ignore[arg-type]
        spend_cap=SpendCap(
            currency=kwargs["spend_cap_currency"],  # type: ignore[arg-type]
            amount_minor=kwargs["spend_cap_minor"],  # type: ignore[arg-type]
        ),
        max_negotiation_rounds=kwargs["max_negotiation_rounds"],  # type: ignore[arg-type]
        acceptance_window_hours=48,
        silent_acceptance=False,
        disclosure_fields=list(kwargs.get("disclosure_fields") or ()),  # type: ignore[arg-type]
        requires_human_approval_for=list(kwargs["requires_human_approval_for"]),  # type: ignore[arg-type]
        issued_at=now,
        not_before=now,
        expires_at=kwargs["expires_at"],  # type: ignore[arg-type]
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

    def events(self, deal_id: str) -> tuple[object, ...]:
        return self.state.store.events_for(deal_id)


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
    # Pre-share each other's identities (ADR-0012: known-hosts, no PKI).
    authority_state.peers[counterparty_state.identity.identity_id] = counterparty_state.identity
    counterparty_state.peers[authority_state.identity.identity_id] = authority_state.identity

    deal_id = new_ulid()
    record = sign_record(
        authority_state.signer,
        counterparty_id=counterparty_state.identity.identity_id,
        # The agent sits on the counterparty's box, so its id is the agent id.
        agent_id=counterparty_state.identity.identity_id,
    )
    now = now_iso()
    register_deal(authority_state, deal_id, record, now)
    # The counterparty also keeps the deal (it records boundary events it
    # originates in its own ledger).
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
    idempotency_key = new_ulid()  # one key does wire-dedup + anti-replay duty
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action=action,
            deal_id=pair.deal_id,
            amount_minor=amount,
            currency=pair.record.spend_cap.currency,
            disclosure_fields=[],
            idempotency_key=idempotency_key,
        ),
        sender=cp.identity,
        recipient_id=pair.authority.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=idempotency_key,
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


def _decision_outcome(response: httpx.Response) -> str:
    body = response.json()
    receipt = WireEnvelope.model_validate(body["receipt"])
    payload = receipt.payload
    assert payload["decision"] is not None, "proposal receipt carried no decision"
    return payload["decision"]["outcome"]


def test_health_reports_identity(pair: Pair) -> None:
    response = pair.authority.client.get(f"{pair.authority.base_url}/health")
    assert response.status_code == 200
    assert response.json()["identity_id"] == pair.authority.state.identity.identity_id


def test_deal_walks_the_wire_and_ledger_verifies(pair: Pair) -> None:
    # DRAFT -> QUOTE_REQUESTED (agent proposal, allowed)
    r = pair.authority.post(_proposal(pair, action="request_quote"))
    assert r.status_code == 200, r.text
    assert _decision_outcome(r) == "allow"
    assert pair.authority.state.store.get_deal(pair.deal_id).state.value == "QUOTE_REQUESTED"

    # QUOTE_REQUESTED -> QUOTE_RECEIVED (passive counterparty event)
    r = pair.authority.post(_counterparty_event(pair, event="quote_received"))
    assert r.status_code == 200, r.text
    assert pair.authority.state.store.get_deal(pair.deal_id).state.value == "QUOTE_RECEIVED"

    # QUOTE_RECEIVED -> AGREED (agent proposal with amount; cumulative spend applied)
    r = pair.authority.post(_proposal(pair, action="accept_agreement", amount=50_000))
    assert r.status_code == 200, r.text
    assert _decision_outcome(r) == "allow"
    deal = pair.authority.state.store.get_deal(pair.deal_id)
    assert deal.state.value == "AGREED"
    assert deal.committed_minor == 50_000

    # AGREED -> IN_PROGRESS
    r = pair.authority.post(_proposal(pair, action="start_work"))
    assert r.status_code == 200, r.text
    assert pair.authority.state.store.get_deal(pair.deal_id).state.value == "IN_PROGRESS"

    # IN_PROGRESS -> COMPLETED (counterparty event)
    r = pair.authority.post(_counterparty_event(pair, event="completion_claimed"))
    assert r.status_code == 200, r.text
    assert pair.authority.state.store.get_deal(pair.deal_id).state.value == "COMPLETED"

    # COMPLETED -> ACCEPTANCE_WINDOW (counterparty event)
    r = pair.authority.post(_counterparty_event(pair, event="acceptance_window_opened"))
    assert r.status_code == 200, r.text
    assert pair.authority.state.store.get_deal(pair.deal_id).state.value == "ACCEPTANCE_WINDOW"

    # The authority's whole evidence trail reconstructs clean.
    a_key = pair.authority.state.signer.public_key
    report = verify_chain(pair.authority.events(pair.deal_id), a_key)
    assert report.ok, report.first_failure()


def test_receipt_is_a_signed_envelope(pair: Pair) -> None:
    r = pair.authority.post(_proposal(pair, action="request_quote"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["outcome"] == "accepted"
    receipt = WireEnvelope.model_validate(body["receipt"])
    assert receipt.kind is MessageKind.RECEIPT
    assert receipt.sender_id == pair.authority.state.identity.identity_id
    assert receipt.recipient_id == pair.counterparty.state.identity.identity_id
    # The receipt verifies against the authority's registered identity key.
    authority_identity = pair.counterparty.state.peers[pair.authority.state.identity.identity_id]
    verify_envelope(receipt, authority_identity)


def test_replayed_message_is_idempotent_no_duplicate(pair: Pair) -> None:
    env = _proposal(pair, action="request_quote")
    first = pair.authority.post(env)
    assert first.status_code == 200, first.text
    count_before = len(pair.authority.events(pair.deal_id))

    # Byte-identical redelivery returns the stored answer, commits nothing new.
    second = pair.authority.post(env)
    assert second.status_code == 200
    assert second.json() == first.json()
    assert len(pair.authority.events(pair.deal_id)) == count_before


def _stale_proposal(
    pair: Pair, *, action: str, seconds_old: int, idempotency_key: str | None = None
) -> WireEnvelope:
    """A correctly signed proposal whose `issued_at` is in the past: the
    signature verifies, the timestamp does not pass the freshness window."""
    cp = pair.counterparty.state
    key = idempotency_key if idempotency_key is not None else new_ulid()
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action=action,
            deal_id=pair.deal_id,
            amount_minor=None,
            currency=pair.record.spend_cap.currency,
            disclosure_fields=[],
            idempotency_key=key,
        ),
        sender=cp.identity,
        recipient_id=pair.authority.state.identity.identity_id,
        message_id=new_ulid(),
        idempotency_key=key,
        issued_at=(datetime.now(UTC) - timedelta(seconds=seconds_old)).isoformat(),
    )


def test_stale_first_seen_envelope_is_rejected_no_commit(pair: Pair) -> None:
    pair.authority.state.max_age_seconds = 300
    key = new_ulid()
    env = _stale_proposal(pair, action="request_quote", seconds_old=600, idempotency_key=key)
    count_before = len(pair.authority.events(pair.deal_id))

    r = pair.authority.post(env)
    assert r.status_code == 400
    assert "stale" in r.json()["error"]
    assert len(pair.authority.events(pair.deal_id)) == count_before

    # The rejection happens before the dedup store, so the idempotency key is
    # not poisoned: a fresh retry with the same key proceeds normally.
    retry = _stale_proposal(pair, action="request_quote", seconds_old=0, idempotency_key=key)
    r2 = pair.authority.post(retry)
    assert r2.status_code == 200, r2.text
    assert _decision_outcome(r2) == "allow"


def test_stale_redelivery_still_gets_stored_answer(
    pair: Pair, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair.authority.state.max_age_seconds = 300
    env = _proposal(pair, action="request_quote")
    first = pair.authority.post(env)
    assert first.status_code == 200, first.text

    # Advance the receiver's clock well past the window: if the staleness
    # check ran before the dedup lookup this redelivery would be rejected.
    def _aged_now() -> str:
        return (datetime.now(UTC) + timedelta(seconds=600)).isoformat()

    monkeypatch.setattr("mandate.transport.gateway.now_iso", _aged_now)
    second = pair.authority.post(env)
    assert second.status_code == 200
    assert second.json() == first.json()


def _local_transition(pair: Pair, event: DealEvent, actor_kind: ActorKind) -> None:
    """The counterparty records a transition it observed/originated in its own chain."""
    cp = pair.counterparty.state
    now = now_iso()
    result = cp.store.commit_transition(
        TransitionRequest(
            deal_id=pair.deal_id,
            command_id=new_ulid(),
            event=event,
            actor_kind=actor_kind,
            actor_id=cp.identity.identity_id,
            authority_record_id=None,
            amount_minor=None,
            occurred_at=now,
            recorded_at=now,
        ),
        cp.signer,
    )
    assert result.outcome.value == "committed", result.detail


def test_both_ledgers_verify_independently(pair: Pair) -> None:
    # A advances across the wire; B mirrors the state it learns from the
    # receipt and records the boundary event it originates in its own chain.
    assert pair.authority.post(_proposal(pair, action="request_quote")).status_code == 200
    _local_transition(pair, DealEvent.QUOTE_REQUESTED, ActorKind.SYSTEM)

    _local_transition(pair, DealEvent.QUOTE_RECEIVED, ActorKind.COUNTERPARTY)
    r = pair.authority.post(_counterparty_event(pair, event="quote_received"))
    assert r.status_code == 200, r.text

    a_report = verify_chain(
        pair.authority.events(pair.deal_id), pair.authority.state.signer.public_key
    )
    assert a_report.ok, a_report.first_failure()
    b_report = verify_chain(
        pair.counterparty.events(pair.deal_id), pair.counterparty.state.signer.public_key
    )
    assert b_report.ok, b_report.first_failure()
    # The two ledgers are distinct evidence, each signed by its own chain key
    # (ADR-0012: identity key != chain key, and the two gateways are separate).
    assert pair.authority.state.signer.key_id != pair.counterparty.state.signer.key_id
