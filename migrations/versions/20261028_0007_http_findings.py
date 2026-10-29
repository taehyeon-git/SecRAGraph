"""Store HTTP finding locations without inventing source file positions."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261028_0007"
down_revision: str | None = "20261027_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("http_method", sa.String(length=16), nullable=True), schema="app"
    )
    op.add_column(
        "findings", sa.Column("http_path", sa.String(length=2048), nullable=True), schema="app"
    )
    op.alter_column(
        "findings", "file_path", schema="app", existing_type=sa.String(length=1024), nullable=True
    )
    op.alter_column(
        "findings", "line_start", schema="app", existing_type=sa.Integer(), nullable=True
    )
    op.create_check_constraint(
        op.f("ck_findings_location_exactly_one"),
        "findings",
        """(
            file_path IS NOT NULL AND line_start IS NOT NULL
            AND http_method IS NULL AND http_path IS NULL
        ) OR (
            file_path IS NULL AND line_start IS NULL AND line_end IS NULL
            AND http_method IS NOT NULL AND http_path IS NOT NULL
        )""",
        schema="app",
    )


def downgrade() -> None:
    # Refuse a downgrade that would discard HTTP findings or falsify their
    # location. Export and remove DAST reports before reverting this schema.
    has_http_findings = op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM app.findings WHERE http_path IS NOT NULL)")
    )
    if has_http_findings:
        raise RuntimeError("cannot downgrade while HTTP findings exist")
    op.drop_constraint(op.f("ck_findings_location_exactly_one"), "findings", schema="app")
    op.alter_column(
        "findings", "line_start", schema="app", existing_type=sa.Integer(), nullable=False
    )
    op.alter_column(
        "findings", "file_path", schema="app", existing_type=sa.String(length=1024), nullable=False
    )
    op.drop_column("findings", "http_path", schema="app")
    op.drop_column("findings", "http_method", schema="app")
