"""make users.last_login_at and users.locked_until timezone-aware

Revision ID: 016_users_timestamps_tz
Revises: 015_users_model_sync
Create Date: 2026-11-12 00:10:00.000000

The login code compares these against datetime.now(UTC). Naive columns make
every login fail with "can't subtract offset-naive and offset-aware datetimes".
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "016_users_timestamps_tz"
down_revision = "015_users_model_sync"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("last_login_at", "locked_until"):
        op.alter_column(
            "users",
            name,
            type_=sa.DateTime(timezone=True),
            existing_type=sa.DateTime(),
            existing_nullable=True,
            postgresql_using=f"{name} AT TIME ZONE 'UTC'",
        )


def downgrade() -> None:
    for name in ("last_login_at", "locked_until"):
        op.alter_column(
            "users",
            name,
            type_=sa.DateTime(),
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=True,
            postgresql_using=f"{name} AT TIME ZONE 'UTC'",
        )
