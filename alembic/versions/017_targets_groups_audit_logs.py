"""target groups and the general audit log

Revision ID: 017_targets_groups_audit_logs
Revises: 016_users_timestamps_tz
Create Date: 2026-11-12 00:20:00.000000

Adds targets.group_name (business-unit grouping in the GUI) and the audit_logs
table written by every account, scan, finding and target change.
Idempotent: skips the column or table when it already exists.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "017_targets_groups_audit_logs"
down_revision = "016_users_timestamps_tz"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    target_columns = {c["name"] for c in inspector.get_columns("targets")}
    if "group_name" not in target_columns:
        op.add_column("targets", sa.Column("group_name", sa.String(length=100), nullable=True))

    if "audit_logs" not in inspector.get_table_names():
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Uuid(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("actor_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("actor_email", sa.String(length=255), nullable=True),
            sa.Column("action", sa.String(length=120), nullable=False),
            sa.Column("resource_type", sa.String(length=60), nullable=False),
            sa.Column("resource_id", sa.String(length=120), nullable=True),
            sa.Column("detail", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_logs" in inspector.get_table_names():
        op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
        op.drop_table("audit_logs")
    if "group_name" in {c["name"] for c in inspector.get_columns("targets")}:
        op.drop_column("targets", "group_name")
