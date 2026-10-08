"""Create normalized scan report storage.

Revision ID: 20260920_0001
Revises:
Create Date: 2026-09-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260920_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.create_table(
        "scan_reports",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("target_name", sa.String(length=512), nullable=False),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("rule_set_version", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("scan_id", name="pk_scan_reports"),
        schema="app",
    )
    op.create_table(
        "findings",
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", sa.String(length=255), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("redacted_evidence", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("cwe_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["app.scan_reports.scan_id"],
            name="fk_findings_scan_id_scan_reports",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("scan_id", "finding_id", name="pk_findings"),
        schema="app",
    )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["app.scan_reports.scan_id"],
            name="fk_audit_events_scan_id_scan_reports",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("event_id", name="pk_audit_events"),
        schema="app",
    )
    op.create_index(
        "ix_audit_events_scan_id",
        "audit_events",
        ["scan_id"],
        unique=False,
        schema="app",
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_scan_id", table_name="audit_events", schema="app")
    op.drop_table("audit_events", schema="app")
    op.drop_table("findings", schema="app")
    op.drop_table("scan_reports", schema="app")
    op.execute("DROP SCHEMA IF EXISTS app")
