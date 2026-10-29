"""Preserve Git commit provenance for historical secret findings."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261030_0008"
down_revision: str | None = "20261028_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("git_commit", sa.String(length=64), nullable=True), schema="app"
    )
    op.create_check_constraint(
        op.f("ck_findings_git_commit_source_location"),
        "findings",
        """git_commit IS NULL OR (
            file_path IS NOT NULL AND line_start IS NOT NULL AND line_start > 0
            AND http_method IS NULL AND http_path IS NULL
            AND git_commit ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
        )""",
        schema="app",
    )


def downgrade() -> None:
    # Dropping provenance would make historical findings appear to refer to
    # the current checkout. Export and remove those reports before reverting.
    has_history = op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM app.findings WHERE git_commit IS NOT NULL)")
    )
    if has_history:
        raise RuntimeError("cannot downgrade while historical findings exist")
    op.drop_constraint(op.f("ck_findings_git_commit_source_location"), "findings", schema="app")
    op.drop_column("findings", "git_commit", schema="app")
