"""add nullable scan user reference

Revision ID: 007_scan_user_id
Revises: 006_bugbounty_gui
Create Date: 2026-05-09 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "007_scan_user_id"
down_revision = "006_bugbounty_gui"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("user_id", sa.Uuid(), nullable=True))
    if op.get_bind().dialect.name == "sqlite":
        return
    op.create_foreign_key("scans_user_id_fkey", "scans", "users", ["user_id"], ["id"])


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("scans_user_id_fkey", "scans", type_="foreignkey")
    op.drop_column("scans", "user_id")
