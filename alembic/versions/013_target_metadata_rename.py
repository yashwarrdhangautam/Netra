"""rename targets.metadata_ to metadata

Revision ID: 013_target_metadata_rename
Revises: 012_target_user_id
Create Date: 2026-11-04 00:10:00.000000

The Target model maps attribute ``metadata_`` to DB column ``"metadata"``
(the standard workaround for SQLAlchemy's reserved ``metadata`` name), but
001_initial_schema created the column as ``metadata_``. ORM inserts therefore
fail with ``table targets has no column named metadata``. Rename to align.
"""
from __future__ import annotations

from alembic import op


revision = "013_target_metadata_rename"
down_revision = "012_target_user_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.alter_column("metadata_", new_column_name="metadata")


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.alter_column("metadata", new_column_name="metadata_")
