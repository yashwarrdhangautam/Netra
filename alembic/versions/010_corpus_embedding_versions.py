"""add corpus embedding model versions

Revision ID: 010_corpus_embedding_versions
Revises: 009_corpus_tables
Create Date: 2026-05-10 00:30:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "010_corpus_embedding_versions"
down_revision = "009_corpus_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bb_corpus_reports", sa.Column("embedding_model_version", sa.String(length=128), nullable=True))
    op.add_column("bb_corpus_writeups", sa.Column("embedding_model_version", sa.String(length=128), nullable=True))
    op.add_column("bb_corpus_advisories", sa.Column("embedding_model_version", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("bb_corpus_advisories", "embedding_model_version")
    op.drop_column("bb_corpus_writeups", "embedding_model_version")
    op.drop_column("bb_corpus_reports", "embedding_model_version")
