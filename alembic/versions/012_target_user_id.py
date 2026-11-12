"""add nullable target user reference

Revision ID: 012_target_user_id
Revises: 011_corpus_pgvector_columns
Create Date: 2026-11-04 00:00:00.000000

The Target model declares ``user_id`` (db/models/target.py) but no migration
ever added it to the ``targets`` table — only 007 added it to ``scans``.
Fresh installs therefore fail to persist a target with
``OperationalError: table targets has no column named user_id``.
This mirrors 007_scan_user_id for consistency.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "012_target_user_id"
down_revision = "011_corpus_pgvector_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("user_id", sa.Uuid(), nullable=True))
    if op.get_bind().dialect.name == "sqlite":
        return
    op.create_foreign_key("targets_user_id_fkey", "targets", "users", ["user_id"], ["id"])


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("targets_user_id_fkey", "targets", type_="foreignkey")
    op.drop_column("targets", "user_id")
