"""Add the wire-message idempotency table (ADR-0012).

One row per (sender, idempotency_key): the envelope fingerprint that first
used the key plus the stored answer. Redelivery of the same envelope returns
the stored answer without reprocessing (invariant 14); the same key with a
different fingerprint is hostile and rejected (ADR-0007, wire level).
"""

from __future__ import annotations

from alembic import op

from mandate.adapters.postgres.db import message_dedup, metadata

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind(), tables=[message_dedup])


def downgrade() -> None:
    metadata.drop_all(bind=op.get_bind(), tables=[message_dedup])
