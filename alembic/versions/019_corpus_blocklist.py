"""right-to-be-forgotten blocklist for the public corpus

Revision ID: 019_corpus_blocklist
Revises: 018_app_settings
Create Date: 2026-11-12 00:40:00.000000

Idempotent: creates the table only when it is missing.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "019_corpus_blocklist"
down_revision = "018_app_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "bb_corpus_blocklist" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "bb_corpus_blocklist",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("kind", sa.String(length=10), nullable=False),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bb_corpus_blocklist_value", "bb_corpus_blocklist", ["value"])


def downgrade() -> None:
    if "bb_corpus_blocklist" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_index("ix_bb_corpus_blocklist_value", table_name="bb_corpus_blocklist")
        op.drop_table("bb_corpus_blocklist")
