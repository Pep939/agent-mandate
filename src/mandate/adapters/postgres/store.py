"""PostgreSQL ledger backend (ADR-0008).

Real transactional atomicity: every commit runs in one database
transaction — read stored state, recheck (invariant 3), append events,
update the deal row, write the seen-store entries. Any failure before
commit rolls back everything. The `uq_events_deal_sequence` constraint is
the last line of defense against a concurrent double-append.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import create_engine, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine

from mandate.adapters.postgres.db import (
    approvals,
    authority_records,
    deal_links,
    deals,
    events,
    idempotency,
    revocations,
    seen_commands,
    seen_nonces,
    seen_requests,
)
from mandate.crypto.signing import GatewaySigner
from mandate.domain.approvals import Approval, ApprovalStatus
from mandate.domain.authority import ActionToken, AuthorityRecord, Revocation
from mandate.domain.deals import Deal, DealState
from mandate.domain.decisions import PolicyDecision
from mandate.domain.events import (
    GENESIS_HASH,
    Event,
    EventSignature,
    EventType,
)
from mandate.domain.input import ActorKind
from mandate.domain.lifecycle import revocation_applies
from mandate.domain.state_machine import transition_for
from mandate.ledger.chain import plan_transition
from mandate.ledger.commit_plans import (
    plan_commit_approval,
    plan_commit_request,
    plan_commit_revocation,
    plan_commit_transition,
)
from mandate.ledger.store import (
    ApprovalDecision,
    ApprovalRequest,
    CommitOutcome,
    CommitRequest,
    CommitResult,
    RevocationRequest,
    TransitionRequest,
)


def _chain_head(conn: Any, deal_id: str) -> tuple[int, str]:
    """(next sequence number, previous event hash) for one deal's chain."""
    head = conn.execute(
        select(events.c.sequence_number, events.c.event_hash)
        .where(events.c.deal_id == deal_id)
        .order_by(events.c.sequence_number.desc())
        .limit(1)
    ).first()
    if head is None:
        return 0, GENESIS_HASH
    return int(head[0]) + 1, head[1]


def _grant_recheck_inputs(
    conn: Any, approval: Approval, occurred_at: str
) -> tuple[AuthorityRecord | None, bool]:
    """The stored parent record and whether any stored revocation applies at
    `occurred_at`, read inside the caller's transaction (ADR-0010 step 2)."""
    rrow = conn.execute(
        select(authority_records).where(
            authority_records.c.record_id == approval.authority_record_id
        )
    ).first()
    record = AuthorityRecord.model_validate(rrow.record) if rrow is not None else None
    if record is None:
        return None, False
    rows = conn.execute(
        select(revocations).where(revocations.c.record_id == record.record_id)
    ).all()
    revoked = any(
        revocation_applies(Revocation.model_validate(r.revocation), record, occurred_at)
        for r in rows
    )
    return record, revoked


def _deal_from_row(row: Any) -> Deal:
    return Deal(
        deal_id=row.deal_id,
        state=DealState(row.state),
        negotiated_rounds=row.negotiated_rounds,
        committed_minor=int(row.committed_minor),
        open_disputes=row.open_disputes,
        open_approvals=row.open_approvals,
    )


def _event_from_row(row: Any) -> Event:
    # Re-validates both hashes at read time: a tampered row cannot even be
    # loaded through the model (belt for the trigger's braces).
    return Event(
        event_id=row.event_id,
        deal_id=row.deal_id,
        sequence_number=int(row.sequence_number),
        event_type=EventType(row.event_type),
        actor_kind=ActorKind(row.actor_kind),
        actor_id=row.actor_id,
        authority_record_id=row.authority_record_id,
        previous_event_hash=row.previous_event_hash,
        payload_hash=row.payload_hash,
        event_hash=row.event_hash,
        payload=row.payload,
        occurred_at=row.occurred_at,
        recorded_at=row.recorded_at,
        signature=EventSignature(
            algorithm=row.sig_algorithm, key_id=row.sig_key_id, value=row.sig_value
        ),
    )


class PostgresLedgerStore:
    """Implements LedgerStore against Postgres (psycopg 3, SQLAlchemy Core)."""

    def __init__(self, db_url: str) -> None:
        self._engine = create_engine(db_url)

    @property
    def engine(self) -> Engine:
        return self._engine

    def close(self) -> None:
        self._engine.dispose()

    # -- deals -------------------------------------------------------------

    def create_deal(self, deal: Deal, created_at: str) -> None:
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(deals.c.deal_id).where(deals.c.deal_id == deal.deal_id)
            ).first()
            if existing is not None:
                msg = f"deal {deal.deal_id} already exists"
                raise ValueError(msg)
            conn.execute(
                insert(deals).values(
                    deal_id=deal.deal_id,
                    state=deal.state.value,
                    negotiated_rounds=deal.negotiated_rounds,
                    committed_minor=deal.committed_minor,
                    open_disputes=deal.open_disputes,
                    open_approvals=deal.open_approvals,
                    created_at=created_at,
                )
            )

    def get_deal(self, deal_id: str) -> Deal | None:
        with self._engine.connect() as conn:
            row = conn.execute(select(deals).where(deals.c.deal_id == deal_id)).first()
        return _deal_from_row(row) if row is not None else None

    def get_deal_created_at(self, deal_id: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(select(deals.c.created_at).where(deals.c.deal_id == deal_id)).first()
        return row[0] if row is not None else None

    def link_deal_record(self, deal_id: str, record_id: str, linked_at: str) -> None:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(deal_links.c.record_id).where(deal_links.c.deal_id == deal_id)
            ).first()
            if row is not None:
                if row.record_id != record_id:
                    msg = f"deal {deal_id} is already linked to record {row.record_id}"
                    raise ValueError(msg)
                return
            conn.execute(
                insert(deal_links).values(deal_id=deal_id, record_id=record_id, linked_at=linked_at)
            )

    def list_deal_links(self) -> dict[str, str]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(deal_links.c.deal_id, deal_links.c.record_id)).all()
        return {r.deal_id: r.record_id for r in rows}

    # -- authority records --------------------------------------------------

    def put_record(self, record: AuthorityRecord) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                insert(authority_records)
                .values(
                    record_id=record.record_id,
                    record=record.model_dump(mode="json"),
                    created_at=record.issued_at,
                )
                .on_conflict_do_nothing()
            )

    def get_record(self, record_id: str) -> AuthorityRecord | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(authority_records).where(authority_records.c.record_id == record_id)
            ).first()
        return AuthorityRecord.model_validate(row.record) if row is not None else None

    def put_revocation(self, revocation: Revocation) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                insert(revocations)
                .values(
                    revocation_id=revocation.revocation_id,
                    record_id=revocation.record_id,
                    revocation=revocation.model_dump(mode="json"),
                    created_at=revocation.revoked_at,
                )
                .on_conflict_do_nothing()
            )

    def list_revocations(self, record_ids: Sequence[str]) -> list[Revocation]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(revocations).where(revocations.c.record_id.in_(list(record_ids)))
            ).all()
        return [Revocation.model_validate(r.revocation) for r in rows]

    # -- anti-replay reads ---------------------------------------------------

    def nonce_owner(self, nonce: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(seen_nonces.c.record_id).where(seen_nonces.c.nonce == nonce)
            ).first()
        return row[0] if row is not None else None

    def seen_request(self, request_id: str) -> bool:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(seen_requests.c.request_id).where(seen_requests.c.request_id == request_id)
            ).first()
        return row is not None

    def decision_for(self, idempotency_key: str) -> tuple[str, PolicyDecision] | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(idempotency).where(idempotency.c.idempotency_key == idempotency_key)
            ).first()
        if row is None:
            return None
        return row.proposal_digest, PolicyDecision.model_validate(row.decision)

    # -- commits -------------------------------------------------------------

    def commit_request(self, req: CommitRequest, signer: GatewaySigner) -> CommitResult:
        with self._engine.begin() as conn:
            # Read-only checks first: every abort path returns before the
            # transaction has written anything, so an abort leaves no
            # partial state — the claims below are the first writes.
            row = conn.execute(select(deals).where(deals.c.deal_id == req.deal_id)).first()
            if row is None:
                return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
            deal = _deal_from_row(row)
            event, abort = plan_transition(deal, req.action, req.decision.outcome)
            if abort is not None:
                return CommitResult(CommitOutcome.STALE_STATE, abort, (), None)

            # Claim-first anti-replay (C3): the claim inserts ARE the gate.
            # An empty RETURNING means a committed (or committing) rival
            # owns the key — bail before any state write; the caller
            # re-gates and the stored verdict answers (invariant 14: a
            # duplicate gets the original answer, never a second commit or
            # a 500). Claim order (idempotency, request, nonce) is global
            # so concurrent commits lock the same rows in the same order.
            # The RETURNING row, not rowcount, is the signal: psycopg 3
            # reports rowcount -1 for ON CONFLICT DO NOTHING.
            claimed = conn.execute(
                insert(idempotency)
                .values(
                    idempotency_key=req.idempotency_key,
                    proposal_digest=req.proposal_digest,
                    decision=req.decision.model_dump(mode="json"),
                )
                .on_conflict_do_nothing()
                .returning(idempotency.c.idempotency_key)
            ).first()
            if claimed is None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    "idempotency key already committed; the stored decision answers",
                    (),
                    None,
                )
            claimed = conn.execute(
                insert(seen_requests)
                .values(request_id=req.request_id)
                .on_conflict_do_nothing()
                .returning(seen_requests.c.request_id)
            ).first()
            if claimed is None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    "request_id already seen; the stored verdict answers",
                    (),
                    None,
                )
            claimed = conn.execute(
                insert(seen_nonces)
                .values(nonce=req.record.nonce, record_id=req.record.record_id)
                .on_conflict_do_nothing()
                .returning(seen_nonces.c.nonce)
            ).first()
            if claimed is None:
                owner = conn.execute(
                    select(seen_nonces.c.record_id).where(seen_nonces.c.nonce == req.record.nonce)
                ).scalar_one()
                if owner != req.record.record_id:
                    return CommitResult(
                        CommitOutcome.ALREADY_APPLIED,
                        "nonce owned by another record; the stored verdict answers",
                        (),
                        None,
                    )

            seq, prev_hash = _chain_head(conn, req.deal_id)
            plan = plan_commit_request(deal, seq, prev_hash, req, event, signer)

            conn.execute(insert(events), [_event_row(e) for e in plan.events])
            if event is not None or plan.approval is not None:
                conn.execute(
                    update(deals)
                    .where(deals.c.deal_id == req.deal_id)
                    .values(
                        state=plan.new_deal.state.value,
                        negotiated_rounds=plan.new_deal.negotiated_rounds,
                        committed_minor=plan.new_deal.committed_minor,
                        open_disputes=plan.new_deal.open_disputes,
                        open_approvals=plan.new_deal.open_approvals,
                    )
                )
            if plan.approval is not None:
                conn.execute(
                    insert(approvals).values(
                        approval_id=plan.approval.approval_id,
                        deal_id=plan.approval.deal_id,
                        status=plan.approval.status.value,
                        approval=plan.approval.model_dump(mode="json"),
                        created_at=plan.approval.created_at,
                    )
                )
            conn.execute(
                insert(authority_records)
                .values(
                    record_id=req.record.record_id,
                    record=req.record.model_dump(mode="json"),
                    created_at=req.record.issued_at,
                )
                .on_conflict_do_nothing()
            )
            return CommitResult(
                CommitOutcome.COMMITTED,
                f"{len(plan.events)} event(s) appended",
                plan.events,
                plan.new_deal,
            )

    def commit_transition(self, req: TransitionRequest, signer: GatewaySigner) -> CommitResult:
        with self._engine.begin() as conn:
            row = conn.execute(select(deals).where(deals.c.deal_id == req.deal_id)).first()
            if row is None:
                return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
            deal = _deal_from_row(row)

            command = conn.execute(
                select(seen_commands.c.command_id).where(
                    seen_commands.c.command_id == req.command_id
                )
            ).first()
            if command is not None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            target = transition_for(deal.state, req.event)
            if target is None:
                return CommitResult(
                    CommitOutcome.STALE_STATE,
                    f"stale_state: event {req.event.value!r} is not valid from stored state "
                    f"{deal.state.value}",
                    (),
                    None,
                )

            # Claim gate (C3): the select above answers sequential retries;
            # this insert is the concurrency gate — a rival that committed
            # between the select and here owns the row, and its event is
            # the answer. It is the transaction's first write, so no abort
            # path above can leave partial state. Empty RETURNING is the
            # signal — psycopg 3 reports rowcount -1 for ON CONFLICT
            # DO NOTHING.
            claimed = conn.execute(
                insert(seen_commands)
                .values(command_id=req.command_id, deal_id=req.deal_id, recorded_at=req.recorded_at)
                .on_conflict_do_nothing()
                .returning(seen_commands.c.command_id)
            ).first()
            if claimed is None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            seq, prev_hash = _chain_head(conn, req.deal_id)
            plan = plan_commit_transition(deal, seq, prev_hash, req, target, signer)

            conn.execute(insert(events), [_event_row(e) for e in plan.events])
            conn.execute(
                update(deals)
                .where(deals.c.deal_id == req.deal_id)
                .values(
                    state=plan.new_deal.state.value,
                    negotiated_rounds=plan.new_deal.negotiated_rounds,
                    committed_minor=plan.new_deal.committed_minor,
                    open_disputes=plan.new_deal.open_disputes,
                    open_approvals=plan.new_deal.open_approvals,
                )
            )
            return CommitResult(
                CommitOutcome.COMMITTED,
                f"{len(plan.events)} event(s) appended",
                plan.events,
                plan.new_deal,
            )

    def commit_approval(self, req: ApprovalRequest, signer: GatewaySigner) -> CommitResult:
        with self._engine.begin() as conn:
            row = conn.execute(select(deals).where(deals.c.deal_id == req.deal_id)).first()
            if row is None:
                return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
            deal = _deal_from_row(row)

            arow = conn.execute(
                select(approvals).where(approvals.c.approval_id == req.approval_id)
            ).first()
            if arow is None:
                return CommitResult(
                    CommitOutcome.APPROVAL_NOT_FOUND, "approval not found", (), None
                )
            approval = Approval.model_validate(arow.approval)
            if approval.status is not ApprovalStatus.PENDING:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"approval {req.approval_id} already {approval.status.value}",
                    (),
                    deal,
                )

            command = conn.execute(
                select(seen_commands.c.command_id).where(
                    seen_commands.c.command_id == req.command_id
                )
            ).first()
            if command is not None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            # Read-only checks (status above, grant inputs here), so every
            # abort returns before this transaction writes anything — the
            # command claim below is the first write.
            token: ActionToken | None = None
            record: AuthorityRecord | None = None
            revoked = False
            if req.operation is ApprovalDecision.GRANTED:
                try:
                    token = ActionToken(req.action)
                except ValueError:
                    return CommitResult(
                        CommitOutcome.STALE_STATE,
                        f"stale_state: unknown action {req.action!r}",
                        (),
                        None,
                    )
                # ADR-0010 steps 2-3 (invariants 3/7): the grant's recheck
                # inputs are read inside this transaction, then resolved by
                # the shared plan.
                record, revoked = _grant_recheck_inputs(conn, approval, req.occurred_at)

            # Claim-first command dedup (C3), as in commit_transition.
            claimed = conn.execute(
                insert(seen_commands)
                .values(command_id=req.command_id, deal_id=req.deal_id, recorded_at=req.recorded_at)
                .on_conflict_do_nothing()
                .returning(seen_commands.c.command_id)
            ).first()
            if claimed is None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            seq, prev_hash = _chain_head(conn, req.deal_id)

            plan = plan_commit_approval(
                deal, approval, seq, prev_hash, req, record, revoked, token, signer
            )
            assert plan.approval is not None  # the plan always decides the approval

            conn.execute(insert(events), [_event_row(e) for e in plan.events])
            conn.execute(
                update(deals)
                .where(deals.c.deal_id == req.deal_id)
                .values(
                    state=plan.new_deal.state.value,
                    negotiated_rounds=plan.new_deal.negotiated_rounds,
                    committed_minor=plan.new_deal.committed_minor,
                    open_disputes=plan.new_deal.open_disputes,
                    open_approvals=plan.new_deal.open_approvals,
                )
            )
            conn.execute(
                update(approvals)
                .where(approvals.c.approval_id == req.approval_id)
                .values(
                    status=plan.approval.status.value,
                    approval=plan.approval.model_dump(mode="json"),
                )
            )
            return CommitResult(
                CommitOutcome.COMMITTED,
                f"{len(plan.events)} event(s) appended",
                plan.events,
                plan.new_deal,
            )

    def commit_revocation(self, req: RevocationRequest, signer: GatewaySigner) -> CommitResult:
        """Record one revocation as a chain event (ADR-0014); same contract as
        the in-memory implementation. All checks and writes run in one
        transaction — a crash mid-commit leaves nothing half-written."""
        with self._engine.begin() as conn:
            row = conn.execute(select(deals).where(deals.c.deal_id == req.deal_id)).first()
            if row is None:
                return CommitResult(CommitOutcome.DEAL_NOT_FOUND, "deal row not found", (), None)
            deal = _deal_from_row(row)

            command = conn.execute(
                select(seen_commands.c.command_id).where(
                    seen_commands.c.command_id == req.command_id
                )
            ).first()
            if command is not None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            rrow = conn.execute(
                select(authority_records).where(
                    authority_records.c.record_id == req.revocation.record_id
                )
            ).first()
            if rrow is None:
                return CommitResult(
                    CommitOutcome.RECORD_NOT_FOUND,
                    f"authority record {req.revocation.record_id} not found",
                    (),
                    deal,
                )

            existing = conn.execute(
                select(revocations.c.revocation_id).where(
                    revocations.c.record_id == req.revocation.record_id
                )
            ).first()
            if existing is not None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"record {req.revocation.record_id} already revoked",
                    (),
                    deal,
                )

            # Claim-first command dedup (C3), as in commit_transition: the
            # checks above are read-only, so this claim is the first write.
            claimed = conn.execute(
                insert(seen_commands)
                .values(command_id=req.command_id, deal_id=req.deal_id, recorded_at=req.recorded_at)
                .on_conflict_do_nothing()
                .returning(seen_commands.c.command_id)
            ).first()
            if claimed is None:
                return CommitResult(
                    CommitOutcome.ALREADY_APPLIED,
                    f"command {req.command_id} already applied",
                    (),
                    deal,
                )

            seq, prev_hash = _chain_head(conn, req.deal_id)
            plan = plan_commit_revocation(deal, seq, prev_hash, req, signer)

            conn.execute(insert(events), [_event_row(e) for e in plan.events])
            conn.execute(
                insert(revocations)
                .values(
                    revocation_id=req.revocation.revocation_id,
                    record_id=req.revocation.record_id,
                    revocation=req.revocation.model_dump(mode="json"),
                    created_at=req.revocation.revoked_at,
                )
                .on_conflict_do_nothing()
            )
            return CommitResult(CommitOutcome.COMMITTED, "1 event appended", plan.events, deal)

    # -- reads ----------------------------------------------------------------

    def get_approval(self, approval_id: str) -> Approval | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(approvals).where(approvals.c.approval_id == approval_id)
            ).first()
        return Approval.model_validate(row.approval) if row is not None else None

    def approvals_for(self, deal_id: str) -> tuple[Approval, ...]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(approvals)
                .where(approvals.c.deal_id == deal_id)
                .order_by(approvals.c.created_at.asc())
            ).all()
        return tuple(Approval.model_validate(r.approval) for r in rows)

    def events_for(self, deal_id: str) -> tuple[Event, ...]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(events)
                .where(events.c.deal_id == deal_id)
                .order_by(events.c.sequence_number.asc())
            ).all()
        return tuple(_event_from_row(r) for r in rows)


def _event_row(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "deal_id": event.deal_id,
        "sequence_number": event.sequence_number,
        "event_type": event.event_type.value,
        "actor_kind": event.actor_kind.value,
        "actor_id": event.actor_id,
        "authority_record_id": event.authority_record_id,
        "previous_event_hash": event.previous_event_hash,
        "payload_hash": event.payload_hash,
        "event_hash": event.event_hash,
        "payload": event.payload,
        "occurred_at": event.occurred_at,
        "recorded_at": event.recorded_at,
        "sig_algorithm": event.signature.algorithm,
        "sig_key_id": event.signature.key_id,
        "sig_value": event.signature.value,
    }
