"""Wire-message idempotency (ADR-0012, invariant 14, ADR-0007 at wire level).

Each gateway keeps one row per `(sender_id, idempotency_key)`: the envelope
fingerprint that first used the key, and the answer it got. A redelivered
envelope returns the stored answer — never reprocessed; the same key with a
different fingerprint is hostile, not a retry, and is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

__all__ = [
    "DedupVerdict",
    "InMemoryWireDedup",
    "StoredAnswer",
    "WireDedup",
]


class DedupVerdict(StrEnum):
    NEW = "new"
    REDELIVERY = "redelivery"
    HOSTILE = "hostile"


@dataclass(frozen=True)
class StoredAnswer:
    """The answer stored for a first-time message: HTTP status + JSON body."""

    status: int
    body: dict[str, object]


@runtime_checkable
class WireDedup(Protocol):
    def lookup(
        self, sender_id: str, idempotency_key: str, fingerprint: str
    ) -> tuple[DedupVerdict, StoredAnswer | None]: ...

    def store(
        self,
        sender_id: str,
        idempotency_key: str,
        fingerprint: str,
        answer: StoredAnswer,
        recorded_at: str,
    ) -> None: ...


class InMemoryWireDedup:
    """Per-process dedup (local/dev gateway setup)."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], tuple[str, StoredAnswer]] = {}

    def lookup(
        self, sender_id: str, idempotency_key: str, fingerprint: str
    ) -> tuple[DedupVerdict, StoredAnswer | None]:
        entry = self._entries.get((sender_id, idempotency_key))
        if entry is None:
            return (DedupVerdict.NEW, None)
        stored_fingerprint, answer = entry
        if stored_fingerprint == fingerprint:
            return (DedupVerdict.REDELIVERY, answer)
        return (DedupVerdict.HOSTILE, None)

    def store(
        self,
        sender_id: str,
        idempotency_key: str,
        fingerprint: str,
        answer: StoredAnswer,
        recorded_at: str,
    ) -> None:
        self._entries[(sender_id, idempotency_key)] = (fingerprint, answer)
