"""add pgvector columns and indexes for corpus retrieval

Revision ID: 011_corpus_pgvector_columns
Revises: 010_corpus_embedding_versions
Create Date: 2026-05-10 00:50:00.000000
"""
from __future__ import annotations

from alembic import op


revision = "011_corpus_pgvector_columns"
down_revision = "010_corpus_embedding_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE bb_corpus_reports ADD COLUMN IF NOT EXISTS embedding_vector vector(768)")
    op.execute("ALTER TABLE bb_corpus_writeups ADD COLUMN IF NOT EXISTS embedding_vector vector(768)")
    op.execute("ALTER TABLE bb_corpus_advisories ADD COLUMN IF NOT EXISTS embedding_vector vector(768)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bb_corpus_reports_embedding_vector "
        "ON bb_corpus_reports USING ivfflat (embedding_vector vector_cosine_ops) WITH (lists = 100)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bb_corpus_writeups_embedding_vector "
        "ON bb_corpus_writeups USING ivfflat (embedding_vector vector_cosine_ops) WITH (lists = 100)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_bb_corpus_advisories_embedding_vector "
        "ON bb_corpus_advisories USING ivfflat (embedding_vector vector_cosine_ops) WITH (lists = 100)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("DROP INDEX IF EXISTS ix_bb_corpus_advisories_embedding_vector")
    op.execute("DROP INDEX IF EXISTS ix_bb_corpus_writeups_embedding_vector")
    op.execute("DROP INDEX IF EXISTS ix_bb_corpus_reports_embedding_vector")
    op.execute("ALTER TABLE bb_corpus_advisories DROP COLUMN IF EXISTS embedding_vector")
    op.execute("ALTER TABLE bb_corpus_writeups DROP COLUMN IF EXISTS embedding_vector")
    op.execute("ALTER TABLE bb_corpus_reports DROP COLUMN IF EXISTS embedding_vector")
