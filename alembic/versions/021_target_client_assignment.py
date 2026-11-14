"""Assign targets to client users, so the client role sees only its own targets.

Revision ID: 021_target_client_assignment
Revises: 020_scan_schedules
"""

import sqlalchemy as sa
from alembic import op

revision = "021_target_client_assignment"
down_revision = "020_scan_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("client_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_targets_client_id_users",
        "targets",
        "users",
        ["client_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_targets_client_id", "targets", ["client_id"])


def downgrade() -> None:
    op.drop_index("ix_targets_client_id", table_name="targets")
    op.drop_constraint("fk_targets_client_id_users", "targets", type_="foreignkey")
    op.drop_column("targets", "client_id")
