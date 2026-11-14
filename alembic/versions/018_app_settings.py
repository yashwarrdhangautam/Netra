"""encrypted app settings table

Revision ID: 018_app_settings
Revises: 017_targets_groups_audit_logs
Create Date: 2026-11-12 00:30:00.000000

Holds integration keys entered in the GUI (Shodan, WPScan, Slack webhook).
Values are encrypted at rest. Idempotent: skips the table if it exists.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "018_app_settings"
down_revision = "017_targets_groups_audit_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "app_settings" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("value_encrypted", sa.Text(), nullable=False),
        sa.Column("updated_by_email", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )


def downgrade() -> None:
    if "app_settings" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("app_settings")
