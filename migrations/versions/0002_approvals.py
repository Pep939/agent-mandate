"""Add the approvals tracking table (ADR-0010).

One row per approval lifecycle: inserted as `pending` when a request
resolves to NEEDS_APPROVAL, updated (same `approval_id`) to `granted` or
`denied` when the operator decides. The signed override + decision live in
the append-only `events` table; this table is the queryable index.
"""

from __future__ import annotations

from alembic import op

from mandate.adapters.postgres.db import approvals, metadata

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind(), tables=[approvals])


def downgrade() -> None:
    metadata.drop_all(bind=op.get_bind(), tables=[approvals])
