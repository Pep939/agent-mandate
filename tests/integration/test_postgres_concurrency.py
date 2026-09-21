"""C3 concurrency gate: identical concurrent requests must commit once.

Pre-fix (select-then-insert, gate outside the commit transaction), two
concurrent identical requests both pass the anti-replay gate and both
commit — the deal state advances twice, or the second writer dies on the
``uq_events_deal_sequence`` unique index (a 500 in the API). Post-fix the
claim inserts run inside the commit transaction: exactly one writer
commits, the state advances once, and nothing raises.

Losers surface in three legitimate shapes depending on where their
statements land relative to the winner's commit:

1. the pre-gate sees the winner's idempotency row → ``IDEMPOTENT_HIT``,
   the duplicate gets the stored verdict (invariant 14), ``commit`` is None;
2. the pre-gate's digest check runs before the winner's commit and its
   request-id check after → ``REPLAY`` (``request_id_reused``), ``commit``
   is None;
3. the pre-gate passes and the deal re-read inside the commit transaction
   sees the advanced state → the plan aborts with ``STALE_STATE``.

Shape 1 is the documented duplicate contract. Shapes 2 and 3 are the same
application-layer gap: a duplicate of an already-applied request can receive
an error answer instead of the stored one. The error is transient — a retry
re-gates and gets the stored verdict, and nothing is corrupted or committed
twice. This test pins the ledger-level guarantee either way: one commit, no
double-advance, no errors.

Gated on MANDATE_TEST_DB_URL like the rest of this package.
"""

from __future__ import annotations

import threading

from tests.support.factories import (
    PAST,
    make_deal,
    make_input,
    make_signer,
    new_ulid,
)

from mandate.application.anti_replay import GateOutcome
from mandate.application.services import ProcessResult, process_request
from mandate.domain.deals import DealEvent, DealState
from mandate.domain.events import EventType
from mandate.domain.input import ActorKind
from mandate.ledger.store import CommitOutcome, TransitionRequest

RECORDED = "2026-01-15T12:00:01Z"
WORKERS = 8


def _race(workers: int, target) -> tuple[list, list[BaseException]]:
    """Run `target` concurrently from N threads behind a barrier.

    Returns (results, errors): errors are exceptions the workers raised —
    a race surfacing as a 500-class failure must be visible here.
    """
    barrier = threading.Barrier(workers)
    results: list = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            r = target()
        except BaseException as e:
            with lock:
                errors.append(e)
            return
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, errors


class TestIdenticalRequestRace:
    def test_one_commit_and_idempotent_answers(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.DRAFT)
        store.create_deal(deal, PAST)
        pi = make_input(deal=deal)  # one request object shared by all workers

        results, errors = _race(
            WORKERS, lambda: process_request(pi, store, signer, recorded_at=RECORDED)
        )
        assert not errors, [repr(e) for e in errors]
        assert len(results) == WORKERS

        # "committed" means the ledger actually committed — a CommitResult
        # with an aborting outcome (STALE_STATE) is not a commit.
        committed = [
            r
            for r in results
            if r.commit is not None and r.commit.outcome is CommitOutcome.COMMITTED
        ]
        assert len(committed) == 1
        assert committed[0].verdict.outcome is GateOutcome.PASS

        winner = committed[0]
        for r in results:
            if r is winner:
                continue
            assert isinstance(r, ProcessResult)
            if r.commit is None:
                # pre-gate short-circuit. Two shapes, both the same
                # duplicate seen through different statement snapshots:
                #   IDEMPOTENT_HIT — the winner's idempotency row is
                #     visible; the duplicate gets the stored verdict, the
                #     original answer (invariant 14), never a
                #     re-evaluation.
                #   REPLAY (request_id_reused) — the gate's digest check
                #     ran before the winner's commit, its request-id check
                #     after; the duplicate gets a replay error instead of
                #     the stored answer. Same application-layer gap as
                #     STALE_STATE below.
                assert r.verdict.outcome in (
                    GateOutcome.IDEMPOTENT_HIT,
                    GateOutcome.REPLAY,
                )
                if r.verdict.outcome is GateOutcome.IDEMPOTENT_HIT:
                    assert r.decision is not None
                    assert r.decision.outcome.value == "allow"
                else:
                    assert r.verdict.detail == "request_id_reused"
            else:
                # interleaved read: the pre-gate passed before the winner
                # committed, then the commit transaction's deal re-read saw
                # the advanced state and the plan aborted. No second commit
                # (counted above) and no error — but this loser got an error
                # answer instead of the stored one; see the module docstring.
                assert r.verdict.outcome is GateOutcome.PASS
                assert r.commit.outcome is CommitOutcome.STALE_STATE

        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.QUOTE_REQUESTED
        assert final.committed_minor == 0
        events = store.events_for(deal.deal_id)
        assert [e.event_type for e in events] == [
            EventType.POLICY_DECISION,
            EventType.STATE_TRANSITION,
        ]


class TestIdenticalCommandRace:
    def test_one_commit_the_rest_already_applied(self, store):
        signer = make_signer()
        deal = make_deal(state=DealState.QUOTE_REQUESTED)
        store.create_deal(deal, PAST)
        req = TransitionRequest(
            deal_id=deal.deal_id,
            command_id=new_ulid(),
            event=DealEvent.QUOTE_RECEIVED,
            actor_kind=ActorKind.SYSTEM,
            actor_id="concurrency-test",
            authority_record_id=None,
            amount_minor=None,
            occurred_at=RECORDED,
            recorded_at=RECORDED,
        )

        results, errors = _race(WORKERS, lambda: store.commit_transition(req, signer))
        assert not errors, [repr(e) for e in errors]
        assert len(results) == WORKERS

        outcomes = [r.outcome for r in results]
        assert outcomes.count(CommitOutcome.COMMITTED) == 1
        for o in outcomes:
            assert o in (CommitOutcome.COMMITTED, CommitOutcome.ALREADY_APPLIED), o

        final = store.get_deal(deal.deal_id)
        assert final is not None
        assert final.state is DealState.QUOTE_RECEIVED
        events = store.events_for(deal.deal_id)
        assert [e.event_type for e in events] == [EventType.STATE_TRANSITION]
