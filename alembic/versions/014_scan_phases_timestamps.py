"""add created_at/updated_at to scan_phases

Revision ID: 014_scan_phases_timestamps
Revises: 013_target_metadata_rename
Create Date: 2026-11-04 00:20:00.000000

Every model inherits created_at/updated_at from Base (db/models/base.py),
but the scan_phases table was created without them, so ORM inserts of a
ScanPhase fail. Added NOT NULL with server_default=now() to match Base.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "014_scan_phases_timestamps"
down_revision = "013_target_metadata_rename"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_phases") as batch:
        batch.add_column(
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            )
        )
        batch.add_column(
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scan_phases") as batch:
        batch.drop_column("updated_at")
        batch.drop_column("created_at")
