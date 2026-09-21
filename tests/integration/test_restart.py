"""Restart safety (C1): a gateway that restarts against the same Postgres
keeps a verifiable chain and keeps pre-existing deals actionable.

The restart is exercised at the process boundary: the key files are re-read
(custody), the store and dedup are rebuilt, and `build_gateway_state`
hydrates the deal → mandate registry from `deal_links`. Gated on
MANDATE_TEST_DB_URL like the rest of this package.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from tests.support.factories import PAST, make_record, new_ulid, write_key_file

from mandate.adapters.postgres.db import create_schema, drop_schema
from mandate.adapters.postgres.store import PostgresLedgerStore
from mandate.adapters.postgres.wire_dedup import PostgresWireDedup
from mandate.crypto.canonicalization import record_signing_payload
from mandate.crypto.signing import ALGORITHM, GatewaySigner, generate_keypair
from mandate.crypto.verification import verify_record
from mandate.domain.authority import SignatureBlock
from mandate.domain.deals import DealEvent
from mandate.domain.input import ActorKind
from mandate.ledger.chain import verify_chain
from mandate.ledger.store import TransitionRequest
from mandate.transport.gateway import (
    build_gateway_state,
    load_chain_signer,
    load_identity,
    register_deal,
)


def _signed_record(signer: GatewaySigner):
    """A mandate signed under the chain key, exactly as the demo does it."""
    unsigned = make_record(
        signature=SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value="")
    )
    value = signer.sign_bytes(record_signing_payload(unsigned))
    return unsigned.model_copy(
        update={"signature": SignatureBlock(algorithm=ALGORITHM, key_id=signer.key_id, value=value)}
    )


def _commit_event(store, deal_id: str, event: DealEvent, signer: GatewaySigner) -> None:
    result = store.commit_transition(
        TransitionRequest(
            deal_id=deal_id,
            command_id=new_ulid(),
            event=event,
            actor_kind=ActorKind.SYSTEM,
            actor_id="restart-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=PAST,
            recorded_at=PAST,
        ),
        signer,
    )
    assert result.outcome.value == "committed", result.detail


def _bootstrap(db_url: str, identity_file: Path, chain_file: Path):
    """The whole process bootstrap: key files -> identity/signer, Postgres store."""
    store = PostgresLedgerStore(db_url)
    return build_gateway_state(
        identity=load_identity(identity_file),
        signer=load_chain_signer(chain_file),
        store=store,
        dedup=PostgresWireDedup(store.engine),
        peers={},
    )


def test_restart_preserves_verifiability(db_url: str, tmp_path: Path) -> None:
    engine = create_engine(db_url)
    drop_schema(engine)
    create_schema(engine)
    engine.dispose()

    identity_priv, _identity_pub = generate_keypair()
    chain_priv, _chain_pub = generate_keypair()
    identity_file = write_key_file(tmp_path, new_ulid(), identity_priv)
    chain_file = write_key_file(tmp_path, new_ulid(), chain_priv)

    try:
        # -- process 1: register a deal, commit two events, die --------------
        state1 = _bootstrap(db_url, identity_file, chain_file)
        deal_id = new_ulid()
        record = _signed_record(state1.signer)
        register_deal(state1, deal_id, record, PAST)
        _commit_event(state1.store, deal_id, DealEvent.QUOTE_REQUESTED, state1.signer)
        _commit_event(state1.store, deal_id, DealEvent.QUOTE_RECEIVED, state1.signer)
        state1.store.close()

        # -- process 2: full re-bootstrap from the same files + DB -----------
        state2 = _bootstrap(db_url, identity_file, chain_file)
        try:
            # The deal → mandate registry hydrated from `deal_links`.
            assert state2.deal_records == {deal_id: record.record_id}
            assert deal_id in state2.deal_ids

            # The chain re-verifies under the reloaded chain key.
            events = state2.store.events_for(deal_id)
            assert len(events) == 2
            report = verify_chain(events, state2.signer.public_key)
            assert report.ok, report.first_failure()

            # The mandate still verifies (key custody: same key, reloaded).
            result = verify_record(record, state2.signer.public_key, state2.signer.key_id)
            assert result.valid, result.reason

            # Pre-existing deals stay actionable across the restart.
            _commit_event(state2.store, deal_id, DealEvent.COUNTEROFFERED, state2.signer)
            events2 = state2.store.events_for(deal_id)
            assert len(events2) == 3
            assert verify_chain(events2, state2.signer.public_key).ok
        finally:
            state2.store.close()
    finally:
        engine = create_engine(db_url)
        drop_schema(engine)
        engine.dispose()
