"""The append-only, tamper-evident event ledger (brief §13).

DB-agnostic core: event model hashing, chain verification, the store
protocol and the in-memory backend. The Postgres backend lives in
`mandate.adapters.postgres` (ADR-0008). No I/O anywhere in this package.
"""

from mandate.ledger.chain import (
    ChainCheck,
    ChainReport,
    build_event,
    make_event_id,
    plan_transition,
    verify_chain,
)
from mandate.ledger.store import (
    CommitOutcome,
    CommitRequest,
    CommitResult,
    InMemoryLedgerStore,
    LedgerStore,
    TransitionRequest,
)

__all__ = [
    "ChainCheck",
    "ChainReport",
    "CommitOutcome",
    "CommitRequest",
    "CommitResult",
    "InMemoryLedgerStore",
    "LedgerStore",
    "TransitionRequest",
    "build_event",
    "make_event_id",
    "plan_transition",
    "verify_chain",
]
