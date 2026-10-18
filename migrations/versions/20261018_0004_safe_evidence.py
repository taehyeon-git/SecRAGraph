"""Remove potentially source-derived evidence from historical findings.

Revision ID: 20261018_0004
Revises: 20260920_0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261018_0004"
down_revision = "20260920_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older evidence was a redacted source line, and may contain other secrets.
    # Irreversibly replace it while retaining report/finding IDs and metadata.
    op.execute(
        sa.text("UPDATE app.findings SET redacted_evidence = 'Legacy source omitted for privacy.'")
    )


def downgrade() -> None:
    # Source text cannot and must not be reconstructed on downgrade.
    pass
