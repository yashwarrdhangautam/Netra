"""Add pgvector extension hook.

Revision ID: 005
Revises: 004_bugbounty_module
Create Date: 2026-05-08
"""
from alembic import op

revision = "005"
down_revision = "004_bugbounty_module"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP EXTENSION IF EXISTS vector")
