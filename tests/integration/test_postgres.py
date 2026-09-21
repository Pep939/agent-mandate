"""Postgres integration tests (gated on MANDATE_TEST_DB_URL).

Suite B tail from the tamper-resistance plan:
- B8: the append-only trigger blocks UPDATE/DELETE on `events`, even for an
  over-privileged connection.
- B9: a failed transaction rolls back cleanly, and command_id idempotency
  makes boundary retries no-ops (invariant 14).
ADR-0014: the revocation lands on the chain as a signed event; the
append-only guard (UPDATE/DELETE/TRUNCATE) covers all nine governed
tables (the 0005 deal-registry table included); the `mandate_app` role
can only read, append and rewrite the two projection tables. Plus a full
lifecycle flow and the Alembic migration equivalence check.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from sqlalchemy import create_engine
from sqlalchemy import exc as sa_exc
from tests.support.factories import (
    PAST,
    make_deal,
    make_input,
    make_proposal,
    make_record,
    make_signer,
    new_ulid,
)

from mandate.adapters.postgres.db import APPEND_ONLY_TABLES, metadata
from mandate.adapters.postgres.store import PostgresLedgerStore
from mandate.adapters.postgres.wire_dedup import PostgresWireDedup
from mandate.application.services import process_request
from mandate.crypto.canonicalization import revocation_signing_payload
from mandate.crypto.signing import make_approval_record
from mandate.crypto.verification import verify_revocation
from mandate.domain.approvals import ApprovalStatus
from mandate.domain.authority import ActionToken, Revocation, SignatureBlock
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.events import EventType
from mandate.domain.input import ActorKind
from mandate.ledger.chain import verify_chain
from mandate.ledger.evidence import build_bundle, verify_bundle
from mandate.ledger.store import (
    ApprovalDecision,
    ApprovalRequest,
    RevocationRequest,
    TransitionRequest,
)
from mandate.transport.dedup import DedupVerdict, StoredAnswer

RECORDED = "2026-01-15T12:00:01Z"


class TestFullFlow:
    def test_lifecycle_on_postgres_verifies(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)

        def step(action: ActionToken, amount: int | None = None) -> None:
            current = store.get_deal(deal.deal_id)
            assert current is not None
            pi = make_input(
                deal=current,
                proposal=make_proposal(
                    action=action.value, deal_id=deal.deal_id, amount_minor=amount, currency="USD"
                ),
            )
            result = process_request(pi, store, signer, recorded_at=RECORDED)
            assert result.decision is not None
            assert result.decision.outcome.value == "allow", (
                f"{action.value}: {result.decision.outcome.value} "
                f"({result.decision.reason_code.value if result.decision.reason_code else ''})"
            )
            assert result.commit is not None
            assert result.commit.outcome.value == "committed"

        step(ActionToken.REQUEST_QUOTE)
        boundary = TransitionRequest(
            deal_id=deal.deal_id,
            command_id=new_ulid(),
            event=DealEvent.QUOTE_RECEIVED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="integration-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=RECORDED,
            recorded_at=RECORDED,
        )
        assert store.commit_transition(boundary, signer).outcome.value == "committed"

        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.QUOTE_RECEIVED

        events = store.events_for(deal.deal_id)
        assert [e.event_type for e in events] == [
            EventType.POLICY_DECISION,
            EventType.STATE_TRANSITION,
            EventType.STATE_TRANSITION,
        ]
        assert verify_chain(events, signer.public_key).ok

        record = make_input().authority.record
        bundle = build_bundle(
            exported_at=RECORDED,
            deal=final,
            deal_created_at=PAST,
            events=events,
            records=[record],
            revocations=[],
            signer=signer,
        )
        assert verify_bundle(bundle, expected_key=signer.public_key).ok


class TestApprovalLifecycle:
    def test_open_and_grant_verifies(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        store.create_deal(deal, PAST)

        # over-cap accept_agreement escalates to approval
        pi = make_input(
            deal=deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=10**9,
                currency="USD",
            ),
        )
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.decision is not None
        assert result.decision.outcome.value == "needs_approval"

        approvals = store.approvals_for(deal.deal_id)
        assert len(approvals) == 1
        approval = approvals[0]
        assert approval.status is ApprovalStatus.PENDING
        assert store.get_deal(deal.deal_id).open_approvals == 1

        record = make_approval_record(
            approval_record_id=new_ulid(),
            deal_id=deal.deal_id,
            request_id=approval.request_id,
            parent_authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            currency=approval.currency,
            proposal_digest=approval.proposal_digest,
            issued_at=RECORDED,
            signer=signer,
        )
        req = ApprovalRequest(
            deal_id=deal.deal_id,
            approval_id=approval.approval_id,
            command_id=new_ulid(),
            operation=ApprovalDecision.GRANTED,
            actor_kind=ActorKind.PRINCIPAL,
            actor_id="integration-test",
            authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            occurred_at=RECORDED,
            recorded_at=RECORDED,
            decided_by="integration-test",
            approval_record=record,
        )
        assert store.commit_approval(req, signer).outcome.value == "committed"

        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.AGREED
        assert final.open_approvals == 0

        events = store.events_for(deal.deal_id)
        assert [e.event_type for e in events] == [
            EventType.POLICY_DECISION,
            EventType.APPROVAL,
            EventType.APPROVAL,
            EventType.STATE_TRANSITION,
        ]
        assert verify_chain(events, signer.public_key).ok
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.GRANTED


class TestGrantRecheck:
    """ADR-0010 steps 2-3 on Postgres: the decision-time recheck reads the
    stored record and revocations inside the commit transaction, and a failed
    recheck becomes a logged deny (invariants 3 and 7)."""

    def _open_approval(self, store, deal, signer):
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        store.create_deal(deal, PAST)
        pi = make_input(
            deal=deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=10**9,
                currency="USD",
            ),
        )
        process_request(pi, store, signer, recorded_at=RECORDED)
        (approval,) = store.approvals_for(deal.deal_id)
        return approval

    def _grant(self, store, deal, approval, signer, **overrides):
        record = make_approval_record(
            approval_record_id=new_ulid(),
            deal_id=deal.deal_id,
            request_id=approval.request_id,
            parent_authority_record_id=approval.authority_record_id,
            action=approval.action,
            amount_minor=approval.amount_minor,
            currency=approval.currency,
            proposal_digest=approval.proposal_digest,
            issued_at=RECORDED,
            signer=signer,
        )
        defaults = {
            "deal_id": deal.deal_id,
            "approval_id": approval.approval_id,
            "command_id": new_ulid(),
            "operation": ApprovalDecision.GRANTED,
            "actor_kind": ActorKind.PRINCIPAL,
            "actor_id": "integration-test",
            "authority_record_id": approval.authority_record_id,
            "action": approval.action,
            "amount_minor": approval.amount_minor,
            "occurred_at": RECORDED,
            "recorded_at": RECORDED,
            "decided_by": "integration-test",
            "approval_record": record,
        }
        defaults.update(overrides)
        return store.commit_approval(ApprovalRequest(**defaults), signer)

    def test_grant_forced_deny_when_parent_revoked(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        store.create_deal(deal, PAST)
        approval = self._open_approval(store, deal, signer)
        record = store.get_record(approval.authority_record_id)
        assert record is not None
        store.put_revocation(
            Revocation(
                schema_version="0.1",
                revocation_id=new_ulid(),
                record_id=record.record_id,
                revoked_at=PAST,
                signature=SignatureBlock(algorithm="Ed25519", key_id="k", value="v"),
            )
        )

        result = self._grant(store, deal, approval, signer)
        assert result.outcome.value == "committed"
        events = store.events_for(deal.deal_id)
        assert events[-1].event_type is EventType.APPROVAL
        assert events[-1].payload["operation"] == "denied"
        assert "no longer current" in events[-1].payload["deny_reason"]
        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.QUOTE_RECEIVED
        assert final.open_approvals == 0
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.DENIED
        assert verify_chain(events, signer.public_key).ok

    def test_grant_forced_deny_when_transition_stale(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.QUOTE_RECEIVED)
        store.create_deal(deal, PAST)
        approval = self._open_approval(store, deal, signer)
        # the deal moves on without the approval: the boundary cancels it
        store.commit_transition(
            TransitionRequest(
                deal_id=deal.deal_id,
                command_id=new_ulid(),
                event=DealEvent.CANCELLED,
                actor_kind=ActorKind.SYSTEM,
                actor_id="boundary",
                authority_record_id=None,
                amount_minor=None,
                occurred_at=RECORDED,
                recorded_at=RECORDED,
            ),
            signer,
        )

        result = self._grant(store, deal, approval, signer)
        assert result.outcome.value == "committed"
        events = store.events_for(deal.deal_id)
        assert events[-1].payload["operation"] == "denied"
        assert "no longer valid" in events[-1].payload["deny_reason"]
        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.CANCELLED
        assert final.open_approvals == 0
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.DENIED
        assert verify_chain(events, signer.public_key).ok


class TestSuiteB8_Trigger:
    def _seed_event(self, store) -> str:
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id))
        process_request(pi, store, signer, recorded_at=RECORDED)
        return deal.deal_id

    def test_update_blocked(self, store):
        deal_id = self._seed_event(store)
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, store.engine.begin() as conn:
            conn.exec_driver_sql(
                "UPDATE events SET payload = payload || '{\"x\":1}'::jsonb "
                "WHERE deal_id = %(deal_id)s",
                {"deal_id": deal_id},
            )
        assert "append-only" in str(excinfo.value)
        # and the row is unchanged
        events = store.events_for(deal_id)
        assert events
        assert "x" not in events[0].payload

    def test_delete_blocked(self, store):
        deal_id = self._seed_event(store)
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, store.engine.begin() as conn:
            conn.exec_driver_sql(
                "DELETE FROM events WHERE deal_id = %(deal_id)s", {"deal_id": deal_id}
            )
        assert "append-only" in str(excinfo.value)
        assert len(store.events_for(deal_id)) == 2

    def test_triggers_exist_in_schema(self, store):
        with store.engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'events'::regclass AND NOT tgisinternal ORDER BY tgname"
            ).all()
        assert [r[0] for r in rows] == ["events_append_only", "events_no_truncate"]


class TestSuiteB9_AtomicityAndIdempotency:
    def test_failed_transaction_rolls_back(self, store):
        """A commit that fails mid-transaction leaves no partial state: the
        appended row is rolled back with the failing statement."""
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id))
        process_request(pi, store, signer, recorded_at=RECORDED)
        before = len(store.events_for(deal.deal_id))

        with pytest.raises(sa_exc.SQLAlchemyError), store.engine.begin() as conn:
            conn.exec_driver_sql(
                "INSERT INTO events (event_id, deal_id, sequence_number, event_type, "
                "actor_kind, actor_id, previous_event_hash, payload_hash, event_hash, "
                "payload, occurred_at, recorded_at, sig_algorithm, sig_key_id, sig_value) "
                "VALUES ('000000000000000000000000ZZ', %(deal_id)s, 999, "
                "'policy_decision', 'agent', 'attacker', "
                "'0000000000000000000000000000000000000000000000000000000000000000', "
                "'abc', 'def', '{}', '2026-01-15T00:00:00Z', '2026-01-15T00:00:00Z', "
                "'Ed25519', 'k', 'v')",
                {"deal_id": deal.deal_id},
            )
            conn.exec_driver_sql("SELECT 1 / 0")
        assert len(store.events_for(deal.deal_id)) == before

    def test_stale_commit_writes_nothing(self, store):
        """The abort path of commit_request must be a no-op (no partial state)."""
        signer = make_signer()
        deal = make_deal(state=DealState.CAPTURED)
        store.create_deal(deal, PAST)
        # the agent claims the deal is still DRAFT, but the store's row is
        # CAPTURED — the engine sees the claim (ALLOW), the store rechecks
        # the stored state and must abort
        stale_claim = make_deal(state=DealState.DRAFT, deal_id=deal.deal_id)
        pi = make_input(deal=stale_claim, proposal=make_proposal(deal_id=deal.deal_id))
        result = process_request(pi, store, signer, recorded_at=RECORDED)
        assert result.commit is not None
        assert result.commit.outcome.value == "stale_state"
        assert store.events_for(deal.deal_id) == ()
        assert store.get_deal(deal.deal_id) == deal
        assert not store.seen_request(pi.request_id)

    def test_command_id_makes_retries_noop(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.QUOTE_REQUESTED)
        store.create_deal(deal, PAST)
        req = TransitionRequest(
            deal_id=deal.deal_id,
            command_id=new_ulid(),
            event=DealEvent.QUOTE_RECEIVED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="integration-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=RECORDED,
            recorded_at=RECORDED,
        )
        assert store.commit_transition(req, signer).outcome.value == "committed"
        assert store.commit_transition(req, signer).outcome.value == "already_applied"
        assert len(store.events_for(deal.deal_id)) == 1
        current = store.get_deal(deal.deal_id)
        assert current is not None
        assert current.state is DealState.QUOTE_RECEIVED


class TestWireDedup:
    """Postgres-backed wire idempotency (ADR-0012, invariant 14): the
    `message_dedup` table and `PostgresWireDedup` backend."""

    def test_new_then_redelivery_returns_stored_answer(self, store):
        dedup = PostgresWireDedup(store.engine)
        assert dedup.lookup("senderA", "key1", "fp1") == (DedupVerdict.NEW, None)

        answer = StoredAnswer(status=200, body={"outcome": "accepted"})
        dedup.store("senderA", "key1", "fp1", answer, RECORDED)

        verdict, stored = dedup.lookup("senderA", "key1", "fp1")
        assert verdict is DedupVerdict.REDELIVERY
        assert stored is not None
        assert stored.status == 200
        assert stored.body == {"outcome": "accepted"}

    def test_same_key_different_fingerprint_is_hostile(self, store):
        dedup = PostgresWireDedup(store.engine)
        dedup.store("senderA", "key1", "fp1", StoredAnswer(status=200, body={}), RECORDED)
        verdict, stored = dedup.lookup("senderA", "key1", "fp-tampered")
        assert verdict is DedupVerdict.HOSTILE
        assert stored is None

    def test_same_key_from_different_sender_is_independent(self, store):
        dedup = PostgresWireDedup(store.engine)
        dedup.store("senderA", "key1", "fp1", StoredAnswer(status=200, body={}), RECORDED)
        # a different sender reusing the key is a fresh message, not a replay
        assert dedup.lookup("senderB", "key1", "fp1") == (DedupVerdict.NEW, None)

    def test_body_jsonb_roundtrip(self, store):
        dedup = PostgresWireDedup(store.engine)
        body = {
            "outcome": "accepted",
            "receipt": {"message_id": "0123456789ABCDEFGHJKMNPQRS", "kind": "receipt"},
        }
        dedup.store("senderA", "key1", "fp1", StoredAnswer(status=200, body=body), RECORDED)
        _, stored = dedup.lookup("senderA", "key1", "fp1")
        assert stored is not None
        assert stored.body == body


class TestCommitRevocation:
    """ADR-0014 on Postgres: the revocation lands on the chain as a signed
    REVOCATION event; retries and double revocations are idempotent no-ops
    (invariant 14); the chain still verifies."""

    def _seed(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id))
        process_request(pi, store, signer, recorded_at=RECORDED)
        record = make_record()
        store.put_record(record)
        return deal, record, signer

    def _signed_revocation(self, record, signer):
        unsigned = Revocation(
            schema_version="0.1",
            revocation_id=new_ulid(),
            record_id=record.record_id,
            revoked_at=PAST,
            signature=SignatureBlock(algorithm="Ed25519", key_id="k", value=""),
        )
        return unsigned.model_copy(
            update={
                "signature": SignatureBlock(
                    algorithm="Ed25519",
                    key_id=signer.key_id,
                    value=signer.sign_bytes(revocation_signing_payload(unsigned)),
                )
            }
        )

    def _req(self, deal, record, signer, **overrides):
        defaults = {
            "deal_id": deal.deal_id,
            "revocation": self._signed_revocation(record, signer),
            "command_id": new_ulid(),
            "actor_kind": ActorKind.PRINCIPAL,
            "actor_id": "integration-test",
            "occurred_at": RECORDED,
            "recorded_at": RECORDED,
        }
        defaults.update(overrides)
        return RevocationRequest(**defaults)

    def test_revocation_committed_and_chain_verifies(self, store):
        deal, record, signer = self._seed(store)
        result = store.commit_revocation(self._req(deal, record, signer), signer)
        assert result.outcome.value == "committed"

        events = store.events_for(deal.deal_id)
        assert [e.event_type for e in events] == [
            EventType.POLICY_DECISION,
            EventType.STATE_TRANSITION,
            EventType.REVOCATION,
        ]
        rev_event = events[-1]
        assert rev_event.authority_record_id == record.record_id
        stored = Revocation.model_validate(rev_event.payload["revocation"])
        assert verify_revocation(stored, signer.public_key).valid
        assert stored == store.list_revocations([record.record_id])[0]
        assert verify_chain(events, signer.public_key).ok

    def test_retry_and_double_revocation_are_noops(self, store):
        deal, record, signer = self._seed(store)
        req = self._req(deal, record, signer)
        assert store.commit_revocation(req, signer).outcome.value == "committed"
        assert store.commit_revocation(req, signer).outcome.value == "already_applied"
        other = self._req(deal, record, signer)
        assert store.commit_revocation(other, signer).outcome.value == "already_applied"
        assert len(store.events_for(deal.deal_id)) == 3
        assert len(store.list_revocations([record.record_id])) == 1

    def test_unknown_record_is_record_not_found(self, store):
        deal, _record, signer = self._seed(store)
        other = make_record()
        result = store.commit_revocation(self._req(deal, other, signer), signer)
        assert result.outcome.value == "record_not_found"


class TestDealLinks:
    """The persistent deal → mandate registry (C1): a restarted process
    rebuilds its deal registry from these rows."""

    def _seed(self, store) -> tuple[str, str]:
        deal = make_deal(state=DealState.DRAFT)
        record = make_record()
        store.create_deal(deal, PAST)
        store.put_record(record)
        return deal.deal_id, record.record_id

    def test_link_and_list_roundtrip(self, store):
        deal_id, record_id = self._seed(store)
        store.link_deal_record(deal_id, record_id, PAST)
        assert store.list_deal_links() == {deal_id: record_id}

    def test_relink_same_pair_is_idempotent(self, store):
        deal_id, record_id = self._seed(store)
        store.link_deal_record(deal_id, record_id, PAST)
        store.link_deal_record(deal_id, record_id, PAST)
        assert store.list_deal_links() == {deal_id: record_id}

    def test_relink_to_different_record_raises(self, store):
        deal_id, record_id = self._seed(store)
        other = make_record()
        store.put_record(other)
        store.link_deal_record(deal_id, record_id, PAST)
        with pytest.raises(ValueError, match="already linked"):
            store.link_deal_record(deal_id, other.record_id, PAST)
        assert store.list_deal_links() == {deal_id: record_id}

    def test_registry_survives_a_new_store_instance(self, store, db_url):
        deal_id, record_id = self._seed(store)
        store.link_deal_record(deal_id, record_id, PAST)
        fresh = PostgresLedgerStore(db_url)
        try:
            assert fresh.list_deal_links() == {deal_id: record_id}
        finally:
            fresh.close()


# One UPDATE per governed table; the column chosen is any non-PK column —
# a BEFORE UPDATE trigger fires even when the values are unchanged.
_APPEND_ONLY_UPDATES = {
    "events": "UPDATE events SET payload = payload",
    "revocations": "UPDATE revocations SET revocation = revocation",
    "authority_records": "UPDATE authority_records SET record = record",
    "deal_links": "UPDATE deal_links SET linked_at = linked_at",
    "seen_nonces": "UPDATE seen_nonces SET record_id = record_id",
    "seen_requests": "UPDATE seen_requests SET request_id = request_id",
    "idempotency": "UPDATE idempotency SET proposal_digest = proposal_digest",
    "seen_commands": "UPDATE seen_commands SET recorded_at = recorded_at",
    "message_dedup": "UPDATE message_dedup SET fingerprint = fingerprint",
}


class TestAppendOnlyGovernedTables:
    """ADR-0014 (amended): UPDATE, DELETE and TRUNCATE all raise on the nine
    governed tables (the 0005 deal-registry table included); the two
    projection tables (deals, approvals) stay writable because the app
    rewrites them by design."""

    def _seed_all_rows(self, store) -> str:
        """One row in every governed table (the app's own writers where they
        have one, a raw INSERT for the seen-stores). Returns the deal_id."""
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id))
        process_request(pi, store, signer, recorded_at=RECORDED)
        record = make_record()
        store.put_record(record)
        store.put_revocation(
            Revocation(
                schema_version="0.1",
                revocation_id=new_ulid(),
                record_id=record.record_id,
                revoked_at=PAST,
                signature=SignatureBlock(algorithm="Ed25519", key_id="k", value="v"),
            )
        )
        store.link_deal_record(deal.deal_id, record.record_id, PAST)
        with store.engine.begin() as conn:
            conn.exec_driver_sql(
                "INSERT INTO seen_nonces (nonce, record_id) VALUES ('nonce-x', %(r)s)",
                {"r": record.record_id},
            )
            conn.exec_driver_sql("INSERT INTO seen_requests (request_id) VALUES ('request-x')")
            conn.exec_driver_sql(
                "INSERT INTO idempotency (idempotency_key, proposal_digest, decision) "
                "VALUES ('key-x', 'fp', '{}')"
            )
            conn.exec_driver_sql(
                "INSERT INTO seen_commands (command_id, deal_id, recorded_at) "
                "VALUES ('command-x', %(d)s, %(t)s)",
                {"d": deal.deal_id, "t": RECORDED},
            )
            conn.exec_driver_sql(
                "INSERT INTO message_dedup (sender_id, idempotency_key, fingerprint, status, "
                "body, created_at) VALUES ('sender-x', 'key-x', 'fp', 200, '{}', %(t)s)",
                {"t": RECORDED},
            )
        return deal.deal_id

    @pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
    def test_update_blocked(self, store, table):
        self._seed_all_rows(store)
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, store.engine.begin() as conn:
            conn.exec_driver_sql(_APPEND_ONLY_UPDATES[table])
        assert "append-only" in str(excinfo.value)

    @pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
    def test_delete_blocked(self, store, table):
        self._seed_all_rows(store)
        # table is a constant from APPEND_ONLY_TABLES, not user input
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, store.engine.begin() as conn:
            conn.exec_driver_sql(f"DELETE FROM {table} WHERE TRUE")  # noqa: S608
        assert "append-only" in str(excinfo.value)

    @pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
    def test_truncate_blocked(self, store, table):
        self._seed_all_rows(store)
        # authority_records is FK-referenced by revocations and deal_links; a
        # lone TRUNCATE of it is rejected by the FK check before any trigger
        # runs, so truncate the closure at once to reach the no-truncate trigger.
        target = (
            "authority_records, revocations, deal_links" if table == "authority_records" else table
        )
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, store.engine.begin() as conn:
            conn.exec_driver_sql(f"TRUNCATE {target}")
        assert "append-only" in str(excinfo.value)

    def test_full_trigger_set(self, store):
        self._seed_all_rows(store)
        with store.engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT tgrelid::regclass::text, tgname FROM pg_trigger "
                "WHERE NOT tgisinternal ORDER BY 1, 2"
            ).all()
        got = {(r[0], r[1]) for r in rows}
        expected = {(t, f"{t}_append_only") for t in APPEND_ONLY_TABLES} | {
            (t, f"{t}_no_truncate") for t in APPEND_ONLY_TABLES
        }
        assert expected == got

    def test_projection_tables_remain_writable(self, store):
        deal_id = self._seed_all_rows(store)
        with store.engine.begin() as conn:
            conn.exec_driver_sql(
                "INSERT INTO approvals (approval_id, deal_id, status, approval, created_at) "
                "VALUES ('approval-x', %(d)s, 'pending', '{}', %(t)s)",
                {"d": deal_id, "t": RECORDED},
            )
            # neither statement may hit an append-only trigger
            conn.exec_driver_sql(
                "UPDATE deals SET state = state WHERE deal_id = %(d)s", {"d": deal_id}
            )
            conn.exec_driver_sql(
                "UPDATE approvals SET status = status WHERE approval_id = 'approval-x'"
            )


class TestMandateAppRole:
    """ADR-0014: the least-privilege role reads and appends, rewrites only
    the two projection tables, and has no DELETE/TRUNCATE/DDL anywhere."""

    APP_USER = "mandate_app"
    APP_PASSWORD = "mandate_app_dev_password_change_me"

    @staticmethod
    def _statements(sql: str) -> list[str]:
        lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
        return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]

    @staticmethod
    def _drop_role(admin) -> None:
        # Grants are objects that depend on the role: revoke them first,
        # otherwise DROP ROLE fails while the schema still exists.
        with admin.connect() as conn:
            exists = conn.exec_driver_sql(
                "SELECT 1 FROM pg_roles WHERE rolname = 'mandate_app'"
            ).first()
            if exists:
                conn.exec_driver_sql("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mandate_app")
                conn.exec_driver_sql("REVOKE ALL ON SCHEMA public FROM mandate_app")
            conn.exec_driver_sql("DROP ROLE IF EXISTS mandate_app")
        admin.dispose()

    @pytest.fixture()
    def app_engine(self, store, db_url):
        # CREATE/DROP ROLE cannot run inside a transaction block
        role_sql = (
            Path(__file__).resolve().parents[2] / "migrations" / "sql" / "roles.sql"
        ).read_text(encoding="utf-8")
        admin = create_engine(db_url, isolation_level="AUTOCOMMIT")
        self._drop_role(admin)
        admin = create_engine(db_url, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            for statement in self._statements(role_sql):
                conn.exec_driver_sql(statement)
        admin.dispose()

        parts = urlsplit(db_url)
        hostport = parts.netloc.rsplit("@", 1)[-1]
        app_url = urlunsplit(
            (
                parts.scheme,
                f"{self.APP_USER}:{self.APP_PASSWORD}@{hostport}",
                parts.path,
                parts.query,
                "",
            )
        )
        engine = create_engine(app_url)
        yield engine
        engine.dispose()
        self._drop_role(create_engine(db_url, isolation_level="AUTOCOMMIT"))

    def test_reads_and_appends(self, store, app_engine):
        record = make_record()
        store.put_record(record)
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        revocation = Revocation(
            schema_version="0.1",
            revocation_id=new_ulid(),
            record_id=record.record_id,
            revoked_at=PAST,
            signature=SignatureBlock(algorithm="Ed25519", key_id="k", value="v"),
        )
        with app_engine.begin() as conn:
            conn.exec_driver_sql("SELECT count(*) FROM events")
            conn.exec_driver_sql("SELECT count(*) FROM deal_links")
            conn.exec_driver_sql(
                "INSERT INTO revocations (revocation_id, record_id, revocation, created_at) "
                "VALUES (%(id)s, %(r)s, %(j)s, %(t)s)",
                {
                    "id": revocation.revocation_id,
                    "r": record.record_id,
                    "j": json.dumps(revocation.model_dump(mode="json")),
                    "t": PAST,
                },
            )
            conn.exec_driver_sql(
                "INSERT INTO deal_links (deal_id, record_id, linked_at) "
                "VALUES (%(d)s, %(r)s, %(t)s)",
                {"d": deal.deal_id, "r": record.record_id, "t": PAST},
            )
        assert store.list_revocations([record.record_id])
        assert store.list_deal_links() == {deal.deal_id: record.record_id}

    def test_cannot_update_governed_table(self, store, app_engine):
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, app_engine.begin() as conn:
            conn.exec_driver_sql("UPDATE events SET payload = payload")
        assert "permission denied" in str(excinfo.value).lower()

    def test_cannot_delete_from_governed_table(self, store, app_engine):
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, app_engine.begin() as conn:
            conn.exec_driver_sql("DELETE FROM revocations WHERE TRUE")
        assert "permission denied" in str(excinfo.value).lower()

    def test_cannot_truncate(self, store, app_engine):
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, app_engine.begin() as conn:
            conn.exec_driver_sql("TRUNCATE events")
        assert "permission denied" in str(excinfo.value).lower()

    def test_can_update_the_two_projection_tables(self, store, app_engine):
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal, proposal=make_proposal(deal_id=deal.deal_id))
        process_request(pi, store, signer, recorded_at=RECORDED)
        with store.engine.begin() as conn:
            conn.exec_driver_sql(
                "INSERT INTO approvals (approval_id, deal_id, status, approval, created_at) "
                "VALUES ('approval-x', %(d)s, 'pending', '{}', %(t)s)",
                {"d": deal.deal_id, "t": RECORDED},
            )
        with app_engine.begin() as conn:
            conn.exec_driver_sql(
                "UPDATE deals SET state = state WHERE deal_id = %(d)s", {"d": deal.deal_id}
            )
            conn.exec_driver_sql(
                "UPDATE approvals SET status = status WHERE approval_id = 'approval-x'"
            )

    def test_cannot_run_ddl(self, store, app_engine):
        with pytest.raises(sa_exc.SQLAlchemyError) as excinfo, app_engine.begin() as conn:
            conn.exec_driver_sql("CREATE TABLE must_fail (i integer)")
        assert "permission denied" in str(excinfo.value).lower()


class TestAlembicMigration:
    def test_migration_matches_create_schema(self, db_url):
        """Running `alembic upgrade head` on a fresh database yields the same
        tables and the full append-only trigger set as create_schema."""
        parts = urlsplit(db_url)
        alt_db = f"{parts.path.strip('/')}_migtest"
        alt_url = urlunsplit((parts.scheme, parts.netloc, f"/{alt_db}", parts.query, ""))

        # CREATE/DROP DATABASE cannot run inside a transaction
        admin = create_engine(db_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.exec_driver_sql(f'CREATE DATABASE "{alt_db}"')
        except sa_exc.SQLAlchemyError as exc:
            pytest.skip(f"cannot create scratch database {alt_db!r}: {type(exc).__name__}")
        admin.dispose()

        try:
            env = dict(os.environ, MANDATE_DB_URL=alt_url)
            proc = subprocess.run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                env=env,
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
            )
            assert proc.returncode == 0, f"alembic failed:\n{proc.stderr}"

            engine = create_engine(alt_url)
            with engine.connect() as conn:
                tables = {
                    r[0]
                    for r in conn.exec_driver_sql(
                        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                    )
                }
                expected = {t.name for t in metadata.tables.values()} | {"alembic_version"}
                assert expected <= tables, f"missing tables: {expected - tables}"
                triggers = {
                    (r[0], r[1])
                    for r in conn.exec_driver_sql(
                        "SELECT tgrelid::regclass::text, tgname FROM pg_trigger "
                        "WHERE NOT tgisinternal"
                    )
                }
                expected_triggers = {(t, f"{t}_append_only") for t in APPEND_ONLY_TABLES} | {
                    (t, f"{t}_no_truncate") for t in APPEND_ONLY_TABLES
                }
                assert expected_triggers <= triggers, (
                    f"missing triggers: {expected_triggers - triggers}"
                )
            engine.dispose()
        finally:
            cleanup = create_engine(db_url, isolation_level="AUTOCOMMIT")
            with cleanup.connect() as conn:
                conn.exec_driver_sql(f'DROP DATABASE IF EXISTS "{alt_db}"')
            cleanup.dispose()
