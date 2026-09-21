"""Wire-gateway abuse (Phase 6, ADR-0012, ADR-0007 at wire level).

A single authority gateway, one registered counterparty peer (the only
legitimate sender), and attacker identities. Every attack must be a 4xx that
commits nothing (invariant 11: externally supplied content is untrusted;
invariant 13: the signature covers the payload; invariant 14: idempotent).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
import pytest
import uvicorn

from mandate.crypto.canonicalization import record_signing_payload
from mandate.crypto.signing import ALGORITHM, GatewaySigner, generate_keypair, sign
from mandate.domain.authority import ActionToken, AuthorityRecord, SignatureBlock, SpendCap
from mandate.ledger.store import InMemoryLedgerStore
from mandate.transport.dedup import InMemoryWireDedup
from mandate.transport.envelope import (
    SCHEMA_VERSION,
    CounterpartyEventPayload,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
    WireEnvelope,
    envelope_signing_payload,
    make_envelope,
)
from mandate.transport.gateway import (
    build_gateway_state,
    create_gateway_app,
    new_ulid,
    now_iso,
    register_deal,
)


def _identity() -> GatewayIdentity:
    private_key, public_key = generate_keypair()
    return GatewayIdentity(identity_id=new_ulid(), public_key=public_key, private_key=private_key)


def _signer() -> GatewaySigner:
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
        purpose="abuse-test mandate",
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
class Rig:
    base_url: str
    authority: object
    deal_id: str
    counterparty: GatewayIdentity
    attacker: GatewayIdentity
    client: httpx.Client
    server: object
    thread: threading.Thread

    def post(self, env: WireEnvelope) -> httpx.Response:
        return self.client.post(f"{self.base_url}/messages", content=env.model_dump_json())

    def post_raw(self, body: bytes) -> httpx.Response:
        return self.client.post(
            f"{self.base_url}/messages", content=body, headers={"Content-Type": "application/json"}
        )

    def events(self) -> tuple[object, ...]:
        return self.authority.store.events_for(self.deal_id)  # type: ignore[attr-defined]

    def deal_state(self) -> str:
        return self.authority.store.get_deal(self.deal_id).state.value  # type: ignore[attr-defined]


@pytest.fixture
def rig() -> Iterator[Rig]:
    counterparty = _identity()
    attacker = _identity()
    authority_identity = _identity()
    state = build_gateway_state(
        identity=authority_identity,
        signer=_signer(),
        store=InMemoryLedgerStore(),
        dedup=InMemoryWireDedup(),
        peers={counterparty.identity_id: counterparty},  # attacker is NOT registered
    )
    deal_id = new_ulid()
    record = _sign_record(
        state.signer, counterparty_id=counterparty.identity_id, agent_id=counterparty.identity_id
    )
    register_deal(state, deal_id, record, now_iso())

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
    base_url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    client = httpx.Client(timeout=10)
    try:
        yield Rig(
            base_url=base_url,
            authority=state,
            deal_id=deal_id,
            counterparty=counterparty,
            attacker=attacker,
            client=client,
            server=server,
            thread=thread,
        )
    finally:
        client.close()
        server.should_exit = True
        thread.join(timeout=5)


def _proposal(
    rig: Rig, *, sender: GatewayIdentity, action: str = "request_quote", idem: str | None = None
) -> WireEnvelope:
    key = idem or new_ulid()
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action=action,
            deal_id=rig.deal_id,
            amount_minor=None,
            currency="USD",
            disclosure_fields=[],
            idempotency_key=key,
        ),
        sender=sender,
        recipient_id=rig.authority.identity.identity_id,  # type: ignore[attr-defined]
        message_id=new_ulid(),
        idempotency_key=key,
        issued_at=now_iso(),
    )


def test_unregistered_sender_is_rejected_and_commits_nothing(rig: Rig) -> None:
    response = rig.post(_proposal(rig, sender=rig.attacker))
    assert response.status_code == 400
    assert "not a registered peer" in response.json()["error"]
    assert rig.events() == ()
    assert rig.deal_state() == "DRAFT"


def test_impersonating_a_registered_peer_with_the_wrong_key_is_rejected(rig: Rig) -> None:
    # The attacker mints an envelope that CLAIMS sender_id = the registered
    # counterparty, but signs it with the attacker's own key.
    spoofed = GatewayIdentity(
        identity_id=rig.counterparty.identity_id,
        public_key=rig.counterparty.public_key,
        private_key=rig.attacker.private_key,
    )
    response = rig.post(_proposal(rig, sender=spoofed))
    assert response.status_code == 400
    assert "signature does not verify" in response.json()["error"]
    assert rig.events() == ()
    assert rig.deal_state() == "DRAFT"


def test_tampered_payload_fails_signature(rig: Rig) -> None:
    original = _proposal(rig, sender=rig.counterparty, action="request_quote")
    # Re-sign-free tamper: same envelope, inflated amount, original signature.
    tampered = WireEnvelope(
        schema_version=SCHEMA_VERSION,
        message_id=original.message_id,
        idempotency_key=original.idempotency_key,
        sender_id=original.sender_id,
        recipient_id=original.recipient_id,
        kind=original.kind,
        payload={**original.payload, "amount_minor": 999_999_999},
        issued_at=original.issued_at,
        signature=original.signature,
    )
    response = rig.post(tampered)
    assert response.status_code == 400
    assert "signature does not verify" in response.json()["error"]
    assert rig.events() == ()


def test_negative_amount_envelope_is_rejected_and_commits_nothing(rig: Rig) -> None:
    # A registered counterparty signs a *valid* envelope whose proposal carries
    # a negative amount. The signature verifies (registered sender, authentic
    # bytes), but the payload fails the domain money rule at the verify-first
    # parse stage: 4xx, nothing committed. This is the wire path the console
    # form parser never sees (invariant 8).
    sender = rig.counterparty
    assert sender.private_key is not None
    payload = {
        "action": "accept_agreement",
        "deal_id": rig.deal_id,
        "amount_minor": -500,
        "currency": "USD",
        "disclosure_fields": [],
        "idempotency_key": new_ulid(),
    }
    provisional = WireEnvelope(
        schema_version=SCHEMA_VERSION,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        sender_id=sender.identity_id,
        recipient_id=rig.authority.identity.identity_id,  # type: ignore[attr-defined]
        kind=MessageKind.PROPOSAL,
        payload=payload,
        issued_at=now_iso(),
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=sender.identity_id, value=""),
    )
    value = sign(sender.private_key, envelope_signing_payload(provisional))
    data = provisional.model_dump(mode="json")
    data["signature"] = {"algorithm": ALGORITHM, "key_id": sender.identity_id, "value": value}
    env = WireEnvelope.model_validate(data)
    response = rig.post(env)
    assert response.status_code == 400
    assert "not a valid proposal payload" in response.json()["error"]
    assert rig.events() == ()
    assert rig.deal_state() == "DRAFT"


def test_idempotency_key_reused_for_different_content_is_hostile(rig: Rig) -> None:
    key = new_ulid()
    first = _proposal(rig, sender=rig.counterparty, action="request_quote", idem=key)
    assert rig.post(first).status_code == 200
    # Same key, different action: a retry would be byte-identical, so this is hostile.
    second = _proposal(rig, sender=rig.counterparty, action="start_work", idem=key)
    response = rig.post(second)
    assert response.status_code == 400
    assert "hostile" in response.json()["error"]
    # Only the first proposal's events exist; the hostile one committed nothing.
    assert len(rig.events()) == 2  # policy_decision + state_transition for request_quote
    assert rig.deal_state() == "QUOTE_REQUESTED"


def test_oversized_body_is_rejected_before_parsing(rig: Rig) -> None:
    body = b"{" + b" " * (64 * 1024 + 1) + b"}"
    response = rig.post_raw(body)
    assert response.status_code == 413
    assert rig.events() == ()


def test_malformed_json_is_rejected(rig: Rig) -> None:
    response = rig.post_raw(b"this is not json")
    assert response.status_code == 400
    assert "not valid JSON" in response.json()["error"]
    assert rig.events() == ()


def test_wrong_recipient_is_rejected(rig: Rig) -> None:
    env = make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action="request_quote",
            deal_id=rig.deal_id,
            amount_minor=None,
            currency="USD",
            disclosure_fields=[],
            idempotency_key=new_ulid(),
        ),
        sender=rig.counterparty,
        recipient_id=rig.attacker.identity_id,  # addressed to someone else
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )
    response = rig.post(env)
    assert response.status_code == 400
    assert "not this gateway" in response.json()["error"]
    assert rig.events() == ()


def test_audience_restricted_mandate_rejects_the_wrong_counterparty(rig: Rig) -> None:
    # A second, correctly-registered peer that is NOT the mandate's audience.
    other = _identity()
    rig.authority.peers[other.identity_id] = other  # type: ignore[attr-defined]
    response = rig.post(_proposal(rig, sender=other, action="request_quote"))
    assert response.status_code == 403
    assert "not the counterparty" in response.json()["error"]
    assert rig.events() == ()
    assert rig.deal_state() == "DRAFT"


def test_unknown_counterparty_event_is_rejected(rig: Rig) -> None:
    env = make_envelope(
        kind=MessageKind.COUNTERPARTY_EVENT,
        payload=CounterpartyEventPayload(
            deal_id=rig.deal_id, event="teleport_to_captured", note=""
        ),
        sender=rig.counterparty,
        recipient_id=rig.authority.identity.identity_id,  # type: ignore[attr-defined]
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )
    response = rig.post(env)
    assert response.status_code == 400
    assert "unknown counterparty event" in response.json()["error"]
    assert rig.deal_state() == "DRAFT"
