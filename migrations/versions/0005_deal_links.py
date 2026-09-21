"""Add `deal_links`, the persistent deal → mandate registry (C1).

A restarted gateway process rebuilds its in-memory deal registry from this
table, so pre-existing deals stay actionable and the chain stays verifiable
after a restart. The table joins the governed set (ADR-0014 addendum):
append-only, with the shared UPDATE/DELETE and TRUNCATE guards.
"""

from __future__ import annotations

from alembic import op

from mandate.adapters.postgres.db import (
    _append_only_drop_sql,
    _trigger_sql_for,
    deal_links,
    metadata,
)

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind(), tables=[deal_links])
    op.execute(_trigger_sql_for(("deal_links",)))


def downgrade() -> None:
    op.execute(_append_only_drop_sql(("deal_links",)))
    metadata.drop_all(bind=op.get_bind(), tables=[deal_links])
