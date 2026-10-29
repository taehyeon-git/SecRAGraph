"""Store image findings without assigning them to source or HTTP locations."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261030_0009"
down_revision: str | None = "20261030_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("image_id", sa.String(length=71), nullable=True), schema="app"
    )
    op.add_column(
        "findings", sa.Column("image_resource", sa.String(length=1024), nullable=True), schema="app"
    )
    op.add_column(
        "findings",
        sa.Column("upstream_severity", sa.String(length=16), nullable=True),
        schema="app",
    )
    op.add_column(
        "findings", sa.Column("severity_source", sa.String(length=64), nullable=True), schema="app"
    )
    op.drop_constraint(op.f("ck_findings_location_exactly_one"), "findings", schema="app")
    op.create_check_constraint(
        op.f("ck_findings_location_exactly_one"),
        "findings",
        """(
            file_path IS NOT NULL AND line_start IS NOT NULL
            AND http_method IS NULL AND http_path IS NULL
            AND image_id IS NULL AND image_resource IS NULL
            AND upstream_severity IS NULL AND severity_source IS NULL
        ) OR (
            file_path IS NULL AND line_start IS NULL AND line_end IS NULL
            AND http_method IS NOT NULL AND http_path IS NOT NULL
            AND git_commit IS NULL
            AND image_id IS NULL AND image_resource IS NULL
            AND upstream_severity IS NULL AND severity_source IS NULL
        ) OR (
            file_path IS NULL AND line_start IS NULL AND line_end IS NULL
            AND http_method IS NULL AND http_path IS NULL AND git_commit IS NULL
            AND image_id IS NOT NULL AND image_resource IS NOT NULL
            AND upstream_severity IS NOT NULL
            AND image_id ~ '^sha256:[0-9a-f]{64}$'
            AND char_length(image_resource) BETWEEN 1 AND 1024
            AND image_resource ~ '^[!-~]+$'
            AND upstream_severity IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        )""",
        schema="app",
    )


def downgrade() -> None:
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM app.findings WHERE image_id IS NOT NULL)")
    ):
        raise RuntimeError("cannot downgrade while image findings exist")
    op.drop_constraint(op.f("ck_findings_location_exactly_one"), "findings", schema="app")
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
    op.drop_column("findings", "severity_source", schema="app")
    op.drop_column("findings", "upstream_severity", schema="app")
    op.drop_column("findings", "image_resource", schema="app")
    op.drop_column("findings", "image_id", schema="app")
