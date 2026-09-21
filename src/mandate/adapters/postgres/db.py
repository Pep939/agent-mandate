"""PostgreSQL schema for the Mandate ledger (ADR-0008).

SQLAlchemy 2.0 Core. The app connects as the least-privilege `mandate_app`
role (`migrations/sql/roles.sql`, ADR-0014: INSERT/SELECT on every table,
UPDATE only on the two projection tables); the append-only triggers below
are the second layer so even an over-privileged role cannot mutate history
(invariant 4, threat model #14/#15).
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine

metadata = MetaData()

deals = Table(
    "deals",
    metadata,
    Column("deal_id", Text, primary_key=True),
    Column("state", Text, nullable=False),
    Column("negotiated_rounds", Integer, nullable=False),
    Column("committed_minor", BigInteger, nullable=False),
    Column("open_disputes", Integer, nullable=False),
    Column("open_approvals", Integer, nullable=False),
    Column("created_at", Text, nullable=False),
)

events = Table(
    "events",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("deal_id", Text, ForeignKey("deals.deal_id"), nullable=False),
    Column("sequence_number", BigInteger, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("actor_kind", Text, nullable=False),
    Column("actor_id", Text, nullable=False),
    Column("authority_record_id", Text),
    Column("previous_event_hash", Text, nullable=False),
    Column("payload_hash", Text, nullable=False),
    Column("event_hash", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("occurred_at", Text, nullable=False),
    Column("recorded_at", Text, nullable=False),
    Column("sig_algorithm", Text, nullable=False),
    Column("sig_key_id", Text, nullable=False),
    Column("sig_value", Text, nullable=False),
    UniqueConstraint("deal_id", "sequence_number", name="uq_events_deal_sequence"),
)

authority_records = Table(
    "authority_records",
    metadata,
    Column("record_id", Text, primary_key=True),
    Column("record", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
)

revocations = Table(
    "revocations",
    metadata,
    Column("revocation_id", Text, primary_key=True),
    Column("record_id", Text, ForeignKey("authority_records.record_id"), nullable=False),
    Column("revocation", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
)

# The persistent deal → mandate registry (C1 restart-safe hydration). One row
# per deal: which signed record authorizes it. Both boundaries write it on
# registration; a restarted process rebuilds its in-memory deal registry from
# it. Immutable once written (re-linking a deal to a different record is a
# store-level error, matching the in-memory backend).
deal_links = Table(
    "deal_links",
    metadata,
    Column("deal_id", Text, ForeignKey("deals.deal_id"), primary_key=True),
    Column("record_id", Text, ForeignKey("authority_records.record_id"), nullable=False),
    Column("linked_at", Text, nullable=False),
)

seen_nonces = Table(
    "seen_nonces",
    metadata,
    Column("nonce", Text, primary_key=True),
    Column("record_id", Text, nullable=False),
)

seen_requests = Table(
    "seen_requests",
    metadata,
    Column("request_id", Text, primary_key=True),
)

idempotency = Table(
    "idempotency",
    metadata,
    Column("idempotency_key", Text, primary_key=True),
    Column("proposal_digest", Text, nullable=False),
    Column("decision", JSONB, nullable=False),
)

seen_commands = Table(
    "seen_commands",
    metadata,
    Column("command_id", Text, primary_key=True),
    Column("deal_id", Text, nullable=False),
    Column("recorded_at", Text, nullable=False),
)

approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", Text, primary_key=True),
    Column("deal_id", Text, ForeignKey("deals.deal_id"), nullable=False),
    Column("status", Text, nullable=False),
    Column("approval", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
)

message_dedup = Table(
    "message_dedup",
    metadata,
    Column("sender_id", Text, primary_key=True),
    Column("idempotency_key", Text, primary_key=True),
    Column("fingerprint", Text, nullable=False),
    Column("status", Integer, nullable=False),
    Column("body", JSONB, nullable=False),
    Column("created_at", Text, nullable=False),
)

# Governed tables: history that must survive — the chain (events), the
# authority side-tables (incl. the deal → mandate registry, ADR-0014
# addendum), and every anti-replay / idempotency store. `deals` and
# `approvals` are deliberately absent: their rows are current-state
# projections (a decision rewrites the `approvals` row; every transition
# rewrites the `deals` row) and their full history is in `events`.
APPEND_ONLY_TABLES: tuple[str, ...] = (
    "events",
    "revocations",
    "authority_records",
    "deal_links",
    "seen_nonces",
    "seen_requests",
    "idempotency",
    "seen_commands",
    "message_dedup",
)

# The one shared guard: row-level UPDATE/DELETE and TRUNCATE both raise.
# The message is a plain string literal: plpgsql requires the RAISE format
# to be a literal (so no TG_TABLE_NAME interpolation), and a literal '%'
# would be parsed as a psycopg placeholder when this DDL runs through a
# parameterised path. The failing statement (and thus the table) is always
# in Postgres' error context.
# The trigger names are `<table>_append_only` / `<table>_no_truncate`.
_TRIGGER_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION mandate_prevent_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'append-only table: mutation rejected (mandate invariant 4)';
END;
$$;
"""


def _trigger_sql_for(tables: tuple[str, ...]) -> str:
    """Shared guard function + one append-only and one no-truncate trigger per
    table. Takes a table subset so each migration only references tables that
    exist at that revision (the chain adds `approvals` and `message_dedup`
    later)."""
    parts = [_TRIGGER_FUNCTION_SQL]
    for table in tables:
        parts.append(
            f"""
DROP TRIGGER IF EXISTS {table}_append_only ON {table};
CREATE TRIGGER {table}_append_only
BEFORE UPDATE OR DELETE ON {table}
FOR EACH ROW EXECUTE FUNCTION mandate_prevent_mutation();
DROP TRIGGER IF EXISTS {table}_no_truncate ON {table};
CREATE TRIGGER {table}_no_truncate
BEFORE TRUNCATE ON {table}
FOR EACH STATEMENT EXECUTE FUNCTION mandate_prevent_mutation();"""
        )
    return "\n".join(parts)


# Full set, used by `create_schema` (tests) and the final migration.
APPEND_ONLY_TRIGGER_SQL = _trigger_sql_for(APPEND_ONLY_TABLES)


def _append_only_drop_sql(tables: tuple[str, ...] | None = None) -> str:
    """Drop the triggers (and, for the full set, the shared function).
    Semicolons are required: this runs as one multi-statement string. Takes a
    table subset for downgrades where later tables do not exist yet."""
    tables = APPEND_ONLY_TABLES if tables is None else tables
    statements = []
    for table in tables:
        statements.append(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table};")
        statements.append(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table};")
    if tables == APPEND_ONLY_TABLES:
        statements.append("DROP FUNCTION IF EXISTS mandate_prevent_mutation();")
    return "\n".join(statements)


def create_schema(engine: Engine) -> None:
    """Tables + append-only triggers (used by integration tests; production
    deploys run the Alembic migration, which runs the same DDL)."""
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql(APPEND_ONLY_TRIGGER_SQL)


def drop_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.exec_driver_sql(_append_only_drop_sql())
    metadata.drop_all(engine)
