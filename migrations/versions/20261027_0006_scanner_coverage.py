"""Persist scanner execution coverage and source-free data-flow locations."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261027_0006"
down_revision: str | None = "20261027_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing reports predate engine coverage and must not be treated as a
    # successful run of the new engines. An empty list means unknown legacy data.
    op.add_column(
        "scan_reports",
        sa.Column(
            "executions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        schema="app",
    )
    op.add_column(
        "findings",
        sa.Column("engine", sa.String(length=64), server_default="secragraph", nullable=False),
        schema="app",
    )
    op.add_column(
        "findings",
        sa.Column(
            "trace",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        schema="app",
    )


def downgrade() -> None:
    op.drop_column("findings", "trace", schema="app")
    op.drop_column("findings", "engine", schema="app")
    op.drop_column("scan_reports", "executions", schema="app")
