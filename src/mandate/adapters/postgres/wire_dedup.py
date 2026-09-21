"""PostgreSQL wire-message idempotency backend (ADR-0012, invariant 14).

Same shape as the ledger store's dedup: check, then insert with
`on_conflict_do_nothing`; the `(sender_id, idempotency_key)` unique
constraint is the backstop against a concurrent double-store. If two
identical messages race past the wire-level check, the lower layers' own
dedup (proposal `idempotency_key`, transition `command_id`) returns the
original decision with no duplicate state (ADR-0007) — defense in depth.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine

from mandate.adapters.postgres.db import message_dedup
from mandate.transport.dedup import DedupVerdict, StoredAnswer

__all__ = ["PostgresWireDedup"]


class PostgresWireDedup:
    """Implements the `WireDedup` protocol against the `message_dedup` table."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def lookup(
        self, sender_id: str, idempotency_key: str, fingerprint: str
    ) -> tuple[DedupVerdict, StoredAnswer | None]:
        with self._engine.begin() as conn:
            row = conn.execute(
                select(message_dedup).where(
                    message_dedup.c.sender_id == sender_id,
                    message_dedup.c.idempotency_key == idempotency_key,
                )
            ).first()
        if row is None:
            return (DedupVerdict.NEW, None)
        if row.fingerprint == fingerprint:
            return (DedupVerdict.REDELIVERY, StoredAnswer(status=row.status, body=row.body))
        return (DedupVerdict.HOSTILE, None)

    def store(
        self,
        sender_id: str,
        idempotency_key: str,
        fingerprint: str,
        answer: StoredAnswer,
        recorded_at: str,
    ) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                insert(message_dedup)
                .values(
                    sender_id=sender_id,
                    idempotency_key=idempotency_key,
                    fingerprint=fingerprint,
                    status=answer.status,
                    body=answer.body,
                    created_at=recorded_at,
                )
                .on_conflict_do_nothing(
                    index_elements=[message_dedup.c.sender_id, message_dedup.c.idempotency_key]
                )
            )
