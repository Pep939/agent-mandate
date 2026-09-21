"""Extend the append-only guard from `events` to all governed tables
(ADR-0014).

One shared trigger function; per table a BEFORE UPDATE OR DELETE row
trigger plus a BEFORE TRUNCATE statement trigger on the eight governed
tables. `deals` and `approvals` stay mutable: they are current-state
projections whose history is in `events` (amended decision 2).

The DDL is generated in `mandate.adapters.postgres.db` so the Alembic chain
and the test schema (`create_schema`) can never drift. `_REV0004_TABLES`
pins the set exactly as it stood at this revision: later migrations add
tables (0005 `deal_links`), and a fresh upgrade must not reference a table
that does not exist yet at this revision.
"""

from __future__ import annotations

from alembic import op

from mandate.adapters.postgres.db import (
    _append_only_drop_sql,
    _trigger_sql_for,
)

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# The governed set as of this revision (before 0005 added `deal_links`).
_REV0004_TABLES: tuple[str, ...] = (
    "events",
    "revocations",
    "authority_records",
    "seen_nonces",
    "seen_requests",
    "idempotency",
    "seen_commands",
    "message_dedup",
)


def upgrade() -> None:
    op.execute(_trigger_sql_for(_REV0004_TABLES))
    # Legacy cleanup: databases upgraded before this migration carry the
    # original single-table guard function.
    op.execute("DROP FUNCTION IF EXISTS mandate_prevent_event_mutation()")


def downgrade() -> None:
    op.execute(_append_only_drop_sql(_REV0004_TABLES))
    # No later revision remains, so the shared function is orphaned too.
    op.execute("DROP FUNCTION IF EXISTS mandate_prevent_mutation()")
