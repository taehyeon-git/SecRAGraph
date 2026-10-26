"""Add local membership accounts, sessions, and report ownership."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20261027_0005"
down_revision: str | None = "20261018_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "members",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(length=32), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("disabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("user_id", name="pk_members"),
        sa.UniqueConstraint("username", name="uq_members_username"),
        schema="app",
    )
    op.create_table(
        "member_sessions",
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("member_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["member_id"],
            ["app.members.user_id"],
            name="fk_member_sessions_member_id_members",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("token_digest", name="pk_member_sessions"),
        schema="app",
    )
    op.create_index("ix_member_sessions_member_id", "member_sessions", ["member_id"], schema="app")
    op.add_column(
        "scan_reports",
        sa.Column("owner_member_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema="app",
    )
    op.create_foreign_key(
        "fk_scan_reports_owner_member_id_members",
        "scan_reports",
        "members",
        ["owner_member_id"],
        ["user_id"],
        source_schema="app",
        referent_schema="app",
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_scan_reports_owner_member_id", "scan_reports", ["owner_member_id"], schema="app"
    )


def downgrade() -> None:
    op.drop_index("ix_scan_reports_owner_member_id", table_name="scan_reports", schema="app")
    op.drop_constraint(
        "fk_scan_reports_owner_member_id_members", "scan_reports", schema="app", type_="foreignkey"
    )
    op.drop_column("scan_reports", "owner_member_id", schema="app")
    op.drop_index("ix_member_sessions_member_id", table_name="member_sessions", schema="app")
    op.drop_table("member_sessions", schema="app")
    op.drop_table("members", schema="app")
