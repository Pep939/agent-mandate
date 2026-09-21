"""Initial schema: deals, events (append-only trigger), authority records,
revocations, and the seen-store tables (ADR-0008/0009).

The DDL is sourced from `mandate.adapters.postgres.db` so the migration and
the test schema can never drift apart.
"""

from __future__ import annotations

from alembic import op

from mandate.adapters.postgres.db import (
    APPEND_ONLY_TABLES,
    _append_only_drop_sql,
    _trigger_sql_for,
    authority_records,
    deals,
    events,
    idempotency,
    metadata,
    revocations,
    seen_commands,
    seen_nonces,
    seen_requests,
)

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# The original Phase-3 tables. `approvals` is added by 0002 so that
# downgrading 0001 does not drop a table the app may still be reading.
_INITIAL_TABLES = [
    deals,
    events,
    authority_records,
    revocations,
    seen_nonces,
    seen_requests,
    idempotency,
    seen_commands,
]

# Only the append-only tables that exist at this revision may carry triggers;
# `message_dedup` arrives in 0003.
_INITIAL_APPEND_ONLY = tuple(
    t for t in APPEND_ONLY_TABLES if t in {x.name for x in _INITIAL_TABLES}
)


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind(), tables=_INITIAL_TABLES)
    op.execute(_trigger_sql_for(_INITIAL_APPEND_ONLY))


def downgrade() -> None:
    op.execute(_append_only_drop_sql(_INITIAL_APPEND_ONLY))
    metadata.drop_all(bind=op.get_bind(), tables=_INITIAL_TABLES)
