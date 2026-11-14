"""sync users table with the User model (verification, lockout, login tracking)

Revision ID: 015_users_model_sync
Revises: 014_scan_phases_timestamps
Create Date: 2026-11-12 00:00:00.000000

The User model gained is_verified, organization, last_login_at,
failed_login_attempts and locked_until, but no migration added them. Login
queries every column, so it failed with "column users.is_verified does not
exist". Each column is added only when it is missing, so this is safe on
databases that were built from the models directly.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "015_users_model_sync"
down_revision = "014_scan_phases_timestamps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("users")}
    additions = [
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("organization", sa.String(length=255), nullable=True),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
    ]
    with op.batch_alter_table("users") as batch:
        for column in additions:
            if column.name not in existing:
                batch.add_column(column)


def downgrade() -> None:
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("users")}
    with op.batch_alter_table("users") as batch:
        for name in (
            "locked_until",
            "failed_login_attempts",
            "last_login_at",
            "organization",
            "is_verified",
        ):
            if name in existing:
                batch.drop_column(name)
