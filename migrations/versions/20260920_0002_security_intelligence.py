"""Create the isolated CVE and CWE intelligence store.

Revision ID: 20260920_0002
Revises: 20260920_0001
Create Date: 2026-09-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260920_0002"
down_revision: str | None = "20260920_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secragraph_reader') THEN
                RAISE EXCEPTION
                    'secragraph_reader role is missing; run the PostgreSQL bootstrap first';
            END IF;
        END
        $$
        """
    )
    # Fail closed if an unexpected actor pre-created this trust-boundary schema.
    op.execute("CREATE SCHEMA intel AUTHORIZATION CURRENT_USER")
    op.execute("REVOKE ALL ON SCHEMA intel FROM PUBLIC")
    op.create_table(
        "cwe",
        sa.Column("cwe_id", sa.String(length=20), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cwe_id ~ '^CWE-[0-9]+$'",
            name="ck_cwe_identifier",
        ),
        sa.PrimaryKeyConstraint("cwe_id", name="pk_cwe"),
        schema="intel",
    )
    op.create_table(
        "cve",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("cwe_id", sa.String(length=20), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=False),
        sa.Column("published_at", sa.Date(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'",
            name="ck_cve_identifier",
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_cve_severity",
        ),
        sa.CheckConstraint(
            "cvss_score >= 0 AND cvss_score <= 10",
            name="ck_cve_cvss_score",
        ),
        sa.ForeignKeyConstraint(
            ["cwe_id"],
            ["intel.cwe.cwe_id"],
            name="fk_cve_cwe_id_cwe",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("cve_id", name="pk_cve"),
        schema="intel",
    )
    op.create_index("ix_cve_cwe_id", "cve", ["cwe_id"], schema="intel")
    op.create_index("ix_cve_vendor", "cve", ["vendor"], schema="intel")

    # The intelligence role must never inherit access to application reports.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE SELECT ON TABLES FROM secragraph_reader"
    )
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA app FROM secragraph_reader")
    op.execute("REVOKE ALL ON SCHEMA app FROM secragraph_reader")
    op.execute("GRANT USAGE ON SCHEMA intel TO secragraph_reader")
    op.execute("GRANT SELECT ON intel.cwe, intel.cve TO secragraph_reader")
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
                current_database()
            );
        END
        $$
        """
    )


def downgrade() -> None:
    op.execute("REVOKE SELECT ON intel.cwe, intel.cve FROM secragraph_reader")
    op.execute("REVOKE USAGE ON SCHEMA intel FROM secragraph_reader")
    op.drop_index("ix_cve_vendor", table_name="cve", schema="intel")
    op.drop_index("ix_cve_cwe_id", table_name="cve", schema="intel")
    op.drop_table("cve", schema="intel")
    op.drop_table("cwe", schema="intel")
    op.execute("DROP SCHEMA IF EXISTS intel")
