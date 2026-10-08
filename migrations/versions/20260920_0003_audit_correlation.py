"""Add request correlation to audit events.

Revision ID: 20260920_0003
Revises: 20260920_0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260920_0003"
down_revision = "20260920_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Historical events predate request correlation; retain them with a nil UUID.
    op.add_column(
        "audit_events",
        sa.Column(
            "correlation_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("'00000000-0000-0000-0000-000000000000'::uuid"),
        ),
        schema="app",
    )
    op.alter_column("audit_events", "correlation_id", server_default=None, schema="app")


def downgrade() -> None:
    op.drop_column("audit_events", "correlation_id", schema="app")
