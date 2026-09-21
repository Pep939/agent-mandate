"""Unit tests for the anti-replay gate (ADR-0007) behind process_request
(ADR-0009). The gate runs against the durable store; seen entries are
written by the commit, atomically with the ledger append."""

from __future__ import annotations

from mandate.application.anti_replay import GateOutcome, check_anti_replay
from mandate.application.services import process_request
from mandate.domain.decisions import Outcome
from mandate.ledger.store import InMemoryLedgerStore
from tests.support.factories import (
    NOW,
    make_deal,
    make_input,
    make_proposal,
    make_signer,
)

PAST_NOW = "2026-01-01T00:00:00Z"


class TestFirstPresentation:
    def test_first_input_passes(self):
        verdict = check_anti_replay(make_input(), InMemoryLedgerStore())
        assert verdict.outcome is GateOutcome.PASS
        assert verdict.decision is None


class TestCrashRetry:
    """A crash-retried request reuses request_id and idempotency_key with an
    identical proposal; it must get the original decision back (invariant 14)."""

    def test_identical_retry_returns_stored_decision_not_replay(self):
        store = InMemoryLedgerStore()
        pi = make_input()
        store.create_deal(pi.deal, PAST_NOW)
        signer = make_signer()

        result = process_request(pi, store, signer, recorded_at=NOW)
        assert result.verdict.outcome is GateOutcome.PASS
        assert result.decision is not None and result.decision.outcome is Outcome.ALLOW
        chain_len = len(store.events_for(pi.deal.deal_id))

        retry = make_input(
            record=pi.authority.record,
            claim=pi.authority,
            deal=pi.deal,
            proposal=pi.proposal,
            actor=pi.actor,
            counterparty=pi.counterparty,
            now=pi.now,
            request_id=pi.request_id,
        )
        result2 = process_request(retry, store, signer, recorded_at=NOW)
        assert result2.verdict.outcome is GateOutcome.IDEMPOTENT_HIT
        assert result2.decision == result.decision
        assert result2.commit is None
        assert len(store.events_for(pi.deal.deal_id)) == chain_len

    def test_denied_proposal_retry_returns_same_denial(self):
        store = InMemoryLedgerStore()
        deal = make_deal()
        store.create_deal(deal, PAST_NOW)
        signer = make_signer()
        pi = make_input(
            deal=deal,
            proposal=make_proposal(action="utterly_unknown_action", deal_id=deal.deal_id),
        )
        result = process_request(pi, store, signer, recorded_at=NOW)
        assert result.verdict.outcome is GateOutcome.PASS
        assert result.decision is not None and result.decision.outcome is Outcome.DENY

        retry = make_input(
            record=pi.authority.record,
            deal=pi.deal,
            proposal=pi.proposal,
            request_id=pi.request_id,
        )
        result2 = process_request(retry, store, signer, recorded_at=NOW)
        assert result2.verdict.outcome is GateOutcome.IDEMPOTENT_HIT
        assert result2.decision == result.decision


class TestIdempotencyConflict:
    def test_same_key_different_proposal_conflicts(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        pi1 = make_input()
        store.create_deal(pi1.deal, PAST_NOW)
        result1 = process_request(pi1, store, signer, recorded_at=NOW)
        assert result1.verdict.outcome is GateOutcome.PASS

        # same idempotency key, different action
        pi2 = make_input(
            record=pi1.authority.record,
            deal=pi1.deal,
            proposal=make_proposal(
                action="cancel_deal",
                deal_id=pi1.deal.deal_id,
                idempotency_key=pi1.proposal.idempotency_key,
            ),
        )
        result2 = process_request(pi2, store, signer, recorded_at=NOW)
        assert result2.verdict.outcome is GateOutcome.CONFLICT
        assert result2.decision is None
        assert result2.commit is None

    def test_same_key_different_amount_conflicts(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        deal = make_deal()
        store.create_deal(deal, PAST_NOW)
        pi1 = make_input(
            deal=deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=1000,
                currency="USD",
            ),
        )
        process_request(pi1, store, signer, recorded_at=NOW)
        pi2 = make_input(
            record=pi1.authority.record,
            deal=deal,
            proposal=make_proposal(
                action="accept_agreement",
                deal_id=deal.deal_id,
                amount_minor=2000,
                currency="USD",
                idempotency_key=pi1.proposal.idempotency_key,
            ),
        )
        result2 = process_request(pi2, store, signer, recorded_at=NOW)
        assert result2.verdict.outcome is GateOutcome.CONFLICT


class TestRequestReplay:
    def test_reused_request_id_with_new_proposal_replays(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        pi1 = make_input()
        store.create_deal(pi1.deal, PAST_NOW)
        process_request(pi1, store, signer, recorded_at=NOW)
        # fresh idempotency key, but the old request_id
        pi2 = make_input(record=pi1.authority.record, deal=pi1.deal, request_id=pi1.request_id)
        verdict = check_anti_replay(pi2, store)
        assert verdict.outcome is GateOutcome.REPLAY
        assert verdict.detail == "request_id_reused"


class TestNonce:
    def test_nonce_collision_across_records_replays(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        rec_a = make_input().authority.record
        pi_a = make_input(record=rec_a)
        store.create_deal(pi_a.deal, PAST_NOW)
        process_request(pi_a, store, signer, recorded_at=NOW)
        # a different record claiming rec_a's nonce
        rec_b = make_input().authority.record
        forged = rec_b.model_copy(update={"nonce": rec_a.nonce})
        pi_b = make_input(record=forged)
        verdict = check_anti_replay(pi_b, store)
        assert verdict.outcome is GateOutcome.REPLAY
        assert verdict.detail == "nonce_reused_by_different_record"

    def test_representing_the_same_record_is_not_a_replay(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        rec = make_input().authority.record
        pi1 = make_input(record=rec)
        store.create_deal(pi1.deal, PAST_NOW)
        process_request(pi1, store, signer, recorded_at=NOW)
        # a second, fresh request under the same (already registered) record
        pi2 = make_input(record=rec, deal=make_input().deal)
        verdict = check_anti_replay(pi2, store)
        assert verdict.outcome is GateOutcome.PASS

    def test_original_nonce_owner_is_not_overwritten_by_forger(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        rec_a = make_input().authority.record
        pi_a = make_input(record=rec_a)
        store.create_deal(pi_a.deal, PAST_NOW)
        process_request(pi_a, store, signer, recorded_at=NOW)
        rec_b = make_input().authority.record
        forged = rec_b.model_copy(update={"nonce": rec_a.nonce})
        check_anti_replay(make_input(record=forged), store)
        assert store.nonce_owner(rec_a.nonce) == rec_a.record_id


class TestRejectedRequestsWriteNothing:
    def test_replay_verdict_bypasses_engine_and_ledger(self):
        store = InMemoryLedgerStore()
        signer = make_signer()
        pi1 = make_input()
        store.create_deal(pi1.deal, PAST_NOW)
        process_request(pi1, store, signer, recorded_at=NOW)
        chain_len = len(store.events_for(pi1.deal.deal_id))

        pi2 = make_input(record=pi1.authority.record, deal=pi1.deal, request_id=pi1.request_id)
        result = process_request(pi2, store, signer, recorded_at=NOW)
        assert result.verdict.outcome is GateOutcome.REPLAY
        assert result.decision is None
        assert result.commit is None
        assert len(store.events_for(pi1.deal.deal_id)) == chain_len
