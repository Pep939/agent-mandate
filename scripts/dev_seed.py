"""Seed a demo deal through the full lifecycle and export its evidence bundle.

Self-contained: runs entirely on the in-memory store, no database required.
Generates an ephemeral gateway key in memory (key_id printed only — the seed
is never persisted, invariant 12).

Usage: uv run scripts/dev_seed.py [--out evidence-demo]
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from mandate.application.services import process_request
from mandate.crypto.canonicalization import revocation_signing_payload
from mandate.crypto.signing import GatewaySigner, generate_keypair
from mandate.domain.authority import (
    ActionToken,
    AuthorityClaim,
    AuthorityRecord,
    Revocation,
    SignatureBlock,
    SpendCap,
)
from mandate.domain.deals import Deal, DealEvent, DealState
from mandate.domain.input import Actor, ActorKind, Counterparty, PolicyInput, Proposal
from mandate.ledger.evidence import (
    build_bundle,
    bundle_json,
    render_checksums,
    render_timeline,
    verify_bundle,
)
from mandate.ledger.store import InMemoryLedgerStore, RevocationRequest, TransitionRequest

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    rng = random.SystemRandom()
    ts = int(time.time() * 1000)
    out = []
    for _ in range(10):
        out.append(CROCKFORD[ts % 32])
        ts //= 32
    for _ in range(16):
        out.append(CROCKFORD[rng.getrandbits(5)])
    return "".join(out)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="evidence-demo")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    key_id = new_ulid()
    private_key, public_key = generate_keypair()
    signer = GatewaySigner(key_id=key_id, private_key=private_key, public_key=public_key)

    store = InMemoryLedgerStore()
    deal_id = new_ulid()
    created_at = now_iso()
    deal = Deal(
        deal_id=deal_id,
        state=DealState.DRAFT,
        negotiated_rounds=0,
        committed_minor=0,
        open_disputes=0,
        open_approvals=0,
    )
    record = AuthorityRecord(
        schema_version="0.1",
        record_id=new_ulid(),
        principal_id=new_ulid(),
        agent_id=new_ulid(),
        counterparty_id=None,
        purpose="dev seed demo mandate",
        allowed_actions=list(ActionToken),
        prohibited_actions=[],
        spend_cap=SpendCap(currency="USD", amount_minor=1_000_000),
        max_negotiation_rounds=10,
        acceptance_window_hours=48,
        silent_acceptance=False,
        disclosure_fields=[],
        requires_human_approval_for=[],
        issued_at=created_at,
        not_before=created_at,
        expires_at="2027-01-01T00:00:00Z",
        parent_record_id=None,
        status="active",
        nonce=new_ulid(),
        signature=SignatureBlock(algorithm="ed25519", key_id=key_id, value=""),
    )
    store.create_deal(deal, created_at)

    def step(action: ActionToken, amount: int | None = None) -> None:
        stored = store.get_deal(deal_id)
        assert stored is not None
        pi = PolicyInput(
            schema_version="0.1",
            request_id=new_ulid(),
            now=now_iso(),
            actor=Actor(kind=ActorKind.AGENT, id=record.agent_id),
            authority=AuthorityClaim(
                record=record,
                signature_valid=True,
                delegation_chain=[],
                status=record.status,
            ),
            counterparty=Counterparty(id=None),
            deal=stored,
            proposal=Proposal(
                action=action.value,
                deal_id=deal_id,
                amount_minor=amount,
                currency="USD",
                disclosure_fields=[],
                idempotency_key=new_ulid(),
            ),
        )
        result = process_request(pi, store, signer, recorded_at=now_iso())
        decision = result.decision
        outcome = decision.outcome.value if decision is not None else "gate"
        current = store.get_deal(deal_id)
        state = current.state.value if current is not None else "?"
        print(f"{outcome.upper():6s} {action.value:20s} -> {state}")

    def boundary(event: DealEvent) -> None:
        req = TransitionRequest(
            deal_id=deal_id,
            command_id=new_ulid(),
            event=event,
            actor_kind=ActorKind.SYSTEM,
            actor_id="dev-seed",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=now_iso(),
            recorded_at=now_iso(),
        )
        result = store.commit_transition(req, signer)
        assert result.outcome.value == "committed", f"boundary {event.value}: {result.outcome}"
        current = store.get_deal(deal_id)
        assert current is not None
        print(f"BND    {event.value:20s} -> {current.state.value}")

    print(f"gateway key_id: {key_id} (ephemeral, in-memory only)")
    print(f"deal_id: {deal_id}\n")

    step(ActionToken.REQUEST_QUOTE)
    boundary(DealEvent.QUOTE_RECEIVED)
    step(ActionToken.ACCEPT_AGREEMENT, amount=50_000)
    step(ActionToken.START_WORK)
    step(ActionToken.PROPOSE_CHANGE)
    step(ActionToken.APPROVE_CHANGE_ORDER, amount=12_000)
    step(ActionToken.CLAIM_COMPLETION)
    boundary(DealEvent.ACCEPTANCE_WINDOW_OPENED)
    step(ActionToken.OPEN_DISPUTE)
    # payment while a dispute is open must be denied (invariant 10)
    step(ActionToken.INITIATE_PAYMENT, amount=62_000)
    step(ActionToken.RESOLVE_DISPUTE)
    step(ActionToken.ACCEPT_COMPLETION)
    step(ActionToken.INITIATE_PAYMENT, amount=62_000)
    step(ActionToken.CAPTURE_PAYMENT, amount=62_000)

    # revoke the mandate; the revocation is signed with the gateway key
    unsigned = Revocation(
        schema_version="0.1",
        revocation_id=new_ulid(),
        record_id=record.record_id,
        revoked_at=now_iso(),
        signature=SignatureBlock(algorithm="Ed25519", key_id=key_id, value=""),
    )
    revocation = unsigned.model_copy(
        update={
            "signature": SignatureBlock(
                algorithm="Ed25519",
                key_id=key_id,
                value=signer.sign_bytes(revocation_signing_payload(unsigned)),
            )
        }
    )
    # ADR-0014: the revocation lands on the deal's chain as a REVOCATION event
    result = store.commit_revocation(
        RevocationRequest(
            deal_id=deal_id,
            revocation=revocation,
            command_id=new_ulid(),
            actor_kind=ActorKind.PRINCIPAL,
            actor_id="dev-seed",
            occurred_at=now_iso(),
            recorded_at=now_iso(),
        ),
        signer,
    )
    assert result.outcome.value == "committed", f"revocation: {result.outcome}"

    final_deal = store.get_deal(deal_id)
    assert final_deal is not None
    events = store.events_for(deal_id)
    bundle = build_bundle(
        exported_at=now_iso(),
        deal=final_deal,
        deal_created_at=created_at,
        events=events,
        records=[record],
        revocations=store.list_revocations([record.record_id]),
        signer=signer,
    )

    (out / "bundle.json").write_text(bundle_json(bundle), encoding="utf-8")
    (out / "timeline.md").write_text(render_timeline(bundle), encoding="utf-8")
    (out / "checksums.sha256").write_text(render_checksums(bundle), encoding="utf-8")

    report = verify_bundle(bundle)
    print(f"\nfinal state: {final_deal.state.value} (committed {final_deal.committed_minor} cents)")
    print(f"events: {len(events)}")
    failed = 0
    for check in report.checks:
        if not check.ok:
            failed += 1
            print(f"  FAIL {check.name}: {check.detail}")
    print(
        f"verification: {'ok' if report.ok else 'FAILED'} "
        f"({len(report.checks) - failed}/{len(report.checks)} checks passed)"
    )
    print(f"\nbundle written to {out}/ (bundle.json, timeline.md, checksums.sha256)")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
