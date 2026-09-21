"""Run two gateways on separate machines and narrate a deal crossing the wire.

Spins up two real gateways (uvicorn, in-process, ephemeral 127.0.0.1 ports)
that do NOT share memory: they only exchange signed, idempotent envelopes over
HTTP (ADR-0012). Gateway A is the authority (it owns the deal's ledger and runs
the policy engine); gateway B is the counterparty (it hosts the agent).

  1. the agent (on B) proposes a quote request — allowed, deal -> QUOTE_REQUESTED;
  2. a byte-identical redelivery of step 1 returns the stored answer — no
     duplicate state (invariant 14);
  3. the counterparty (B) reports the incoming quote — deal -> QUOTE_RECEIVED;
  4. the agent proposes a $2,500 agreement against a $1,000 cap — escalated to a
     person, NOT authorized (LLM output grants no authority, invariant 1);
   5. an unregistered attacker proposes on B's behalf — rejected, commits nothing;
   6. A's whole event chain is independently verified and printed.

The counterparty (B) verifies every receipt it receives — signature against
the registered authority identity, `responds_to` bound to its own message id,
freshness window — before reading the decision (Phase 6, ADR-0012).

Usage:
  uv run scripts/two_gateways.py

Exit codes: 0 = the expected demo played out, 1 = something unexpected.
"""

from __future__ import annotations

import sys
import threading
import time

import httpx
import uvicorn

from mandate.crypto.canonicalization import record_signing_payload
from mandate.crypto.signing import ALGORITHM, GatewaySigner, generate_keypair
from mandate.domain.authority import ActionToken, AuthorityRecord, SignatureBlock, SpendCap
from mandate.ledger.chain import verify_chain
from mandate.ledger.store import InMemoryLedgerStore
from mandate.transport.dedup import InMemoryWireDedup
from mandate.transport.envelope import (
    CounterpartyEventPayload,
    GatewayIdentity,
    MessageKind,
    ProposalPayload,
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


def _identity() -> GatewayIdentity:
    private_key, public_key = generate_keypair()
    return GatewayIdentity(identity_id=new_ulid(), public_key=public_key, private_key=private_key)


def _signer() -> GatewaySigner:
    private_key, public_key = generate_keypair()
    return GatewaySigner(key_id=new_ulid(), private_key=private_key, public_key=public_key)


def _sign_record(
    signer: GatewaySigner, *, counterparty_id: str, agent_id: str, cap_minor: int
) -> AuthorityRecord:
    now = now_iso()
    unsigned = AuthorityRecord(
        schema_version="0.1",
        record_id=new_ulid(),
        principal_id=new_ulid(),
        agent_id=agent_id,
        counterparty_id=counterparty_id,
        purpose="Two-gateway demo mandate",
        allowed_actions=[a.value for a in ActionToken],
        prohibited_actions=[],
        spend_cap=SpendCap(currency="USD", amount_minor=cap_minor),
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
    signature = SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=value)
    return unsigned.model_copy(update={"signature": signature})


def _proposal(
    sender: GatewayIdentity, *, recipient_id: str, deal_id: str, action: str, amount: int | None
) -> WireEnvelope:
    key = new_ulid()
    return make_envelope(
        kind=MessageKind.PROPOSAL,
        payload=ProposalPayload(
            action=action,
            deal_id=deal_id,
            amount_minor=amount,
            currency="USD",
            disclosure_fields=[],
            idempotency_key=key,
        ),
        sender=sender,
        recipient_id=recipient_id,
        message_id=new_ulid(),
        idempotency_key=key,
        issued_at=now_iso(),
    )


def _counterparty_event(
    sender: GatewayIdentity, *, recipient_id: str, deal_id: str, event: str
) -> WireEnvelope:
    return make_envelope(
        kind=MessageKind.COUNTERPARTY_EVENT,
        payload=CounterpartyEventPayload(deal_id=deal_id, event=event, note=""),
        sender=sender,
        recipient_id=recipient_id,
        message_id=new_ulid(),
        idempotency_key=new_ulid(),
        issued_at=now_iso(),
    )


class GatewayServer:
    def __init__(self, state: GatewayState) -> None:
        self.state = state
        self.client = httpx.Client(timeout=10)
        app = create_gateway_app(state)
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:
                msg = "gateway did not start in time"
                raise RuntimeError(msg)
            time.sleep(0.01)
        self.base_url = f"http://127.0.0.1:{self.server.servers[0].sockets[0].getsockname()[1]}"

    def post(self, env: WireEnvelope):
        return self.client.post(f"{self.base_url}/messages", content=env.model_dump_json())

    def stop(self) -> None:
        self.client.close()
        self.server.should_exit = True
        self.thread.join(timeout=5)


def _decision_outcome(response, *, authority_identity: GatewayIdentity, sent: WireEnvelope) -> str:
    """Counterparty-side receipt verification (Phase 6, ADR-0012): the
    authority's signature is checked against the registered peer identity,
    `responds_to` is bound to our own message id, and a freshness window
    applies — before the decision outcome is read. A forged, tampered or
    replayed receipt raises EnvelopeError and fails the demo."""
    receipt = WireEnvelope.model_validate(response.json()["receipt"])
    payload = verify_receipt(
        receipt,
        authority_identity,
        expected_responds_to=sent.message_id,
        now=now_iso(),
        max_age_seconds=300,
    )
    assert payload.decision is not None
    return payload.decision["outcome"]


def main() -> int:
    authority = GatewayServer(
        build_gateway_state(
            identity=_identity(),
            signer=_signer(),
            store=InMemoryLedgerStore(),
            dedup=InMemoryWireDedup(),
        )
    )
    counterparty = GatewayServer(
        build_gateway_state(
            identity=_identity(),
            signer=_signer(),
            store=InMemoryLedgerStore(),
            dedup=InMemoryWireDedup(),
        )
    )
    authority.state.peers[counterparty.state.identity.identity_id] = counterparty.state.identity
    counterparty.state.peers[authority.state.identity.identity_id] = authority.state.identity

    deal_id = new_ulid()
    record = _sign_record(
        authority.state.signer,
        counterparty_id=counterparty.state.identity.identity_id,
        agent_id=counterparty.state.identity.identity_id,
        cap_minor=100_000,  # $1,000 cap
    )
    register_deal(authority.state, deal_id, record, now_iso())

    b = counterparty.state.identity
    a_id = authority.state.identity.identity_id
    # The counterparty's view of the authority — the identity its verify path trusts.
    a_identity = counterparty.state.peers[a_id]

    try:
        print(f"authority    {authority.base_url}  (identity {a_id[:12]}…)")
        print(f"counterparty {counterparty.base_url}  (identity {b.identity_id[:12]}…)\n")

        print("1. the agent proposes a quote request")
        quote_request = _proposal(
            b, recipient_id=a_id, deal_id=deal_id, action="request_quote", amount=None
        )
        r = authority.post(quote_request)
        deal = authority.state.store.get_deal(deal_id).state.value
        print(
            f"  agent -> authority: "
            f"{_decision_outcome(r, authority_identity=a_identity, sent=quote_request)}"
            f"  [deal: {deal}]"
        )

        print("\n2. a byte-identical redelivery of step 1 (webhook retry)")
        before = len(authority.state.store.events_for(deal_id))
        r2 = authority.post(quote_request)  # identical envelope, identical bytes
        after = len(authority.state.store.events_for(deal_id))
        idempotent = r.json() == r2.json() and before == after
        print(
            f"  first: {r.status_code}, redelivery: {r2.status_code}, "
            f"same answer: {r.json() == r2.json()}, events {before}->{after}"
        )

        print("\n3. the counterparty reports the incoming quote")
        r = authority.post(
            _counterparty_event(b, recipient_id=a_id, deal_id=deal_id, event="quote_received")
        )
        deal = authority.state.store.get_deal(deal_id).state.value
        print(f"  counterparty -> authority: accepted  [deal: {deal}]")

        print("\n4. the agent proposes $2,500 against a $1,000 cap")
        agreement = _proposal(
            b,
            recipient_id=a_id,
            deal_id=deal_id,
            action="accept_agreement",
            amount=250_000,
        )
        r = authority.post(agreement)
        deal = authority.state.store.get_deal(deal_id).state.value
        print(
            f"  agent -> authority: "
            f"{_decision_outcome(r, authority_identity=a_identity, sent=agreement)}"
            f"  [deal: {deal}]"
        )

        print("\n5. an unregistered attacker proposes on B's behalf")
        attacker = _identity()
        r = authority.post(
            _proposal(
                attacker, recipient_id=a_id, deal_id=deal_id, action="request_quote", amount=None
            )
        )
        print(f"  attacker -> authority: {r.status_code} {r.json()['error']}")

        events = authority.state.store.events_for(deal_id)
        report = verify_chain(events, authority.state.signer.public_key)
        print(
            f"\nevent chain: {len(events)} events, verification: "
            f"{'OK' if report.ok else report.first_failure()}"
        )
        ok = (
            report.ok
            and idempotent
            and authority.state.store.get_deal(deal_id).state.value == "QUOTE_RECEIVED"
            and r.status_code == 400
        )
        return 0 if ok else 1
    finally:
        authority.stop()
        counterparty.stop()


if __name__ == "__main__":
    sys.exit(main())
