"""learning corpus tables

Revision ID: 009_corpus_tables
Revises: 008_agentic_capabilities
Create Date: 2026-05-10 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "009_corpus_tables"
down_revision = "008_agentic_capabilities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bb_corpus_reports",
        sa.Column("source_platform", sa.String(length=32), nullable=False),
        sa.Column("source_url", sa.String(length=1024), nullable=False),
        sa.Column("author_handle", sa.String(length=255), nullable=True),
        sa.Column("program_handle", sa.String(length=255), nullable=True),
        sa.Column("vuln_class", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("body_summary", sa.Text(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("tech_stack", sa.JSON(), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("redaction_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("embedding", sa.JSON(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_url"),
    )
    op.create_index("ix_bb_corpus_reports_source_platform", "bb_corpus_reports", ["source_platform"])
    op.create_index("ix_bb_corpus_reports_program_handle", "bb_corpus_reports", ["program_handle"])
    op.create_index("ix_bb_corpus_reports_vuln_class", "bb_corpus_reports", ["vuln_class"])
    op.create_index("ix_bb_corpus_reports_platform_vuln", "bb_corpus_reports", ["source_platform", "vuln_class"])

    op.create_table(
        "bb_corpus_writeups",
        sa.Column("source_url", sa.String(length=1024), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("vuln_class", sa.String(length=128), nullable=True),
        sa.Column("tech_stack", sa.JSON(), nullable=True),
        sa.Column("body_summary", sa.Text(), nullable=False),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("redaction_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("embedding", sa.JSON(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_url"),
    )
    op.create_index("ix_bb_corpus_writeups_vuln_class", "bb_corpus_writeups", ["vuln_class"])

    op.create_table(
        "bb_corpus_advisories",
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("ghsa_id", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("cvss_vector", sa.String(length=128), nullable=True),
        sa.Column("affected_packages", sa.JSON(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(length=1024), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("embedding", sa.JSON(), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_url"),
    )
    op.create_index("ix_bb_corpus_advisories_cve_id", "bb_corpus_advisories", ["cve_id"])
    op.create_index("ix_bb_corpus_advisories_ghsa_id", "bb_corpus_advisories", ["ghsa_id"])
    op.create_index("ix_bb_corpus_advisories_severity", "bb_corpus_advisories", ["severity"])

    op.create_table(
        "bb_corpus_trends",
        sa.Column("week_starting", sa.Date(), nullable=False),
        sa.Column("vuln_class", sa.String(length=128), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delta_vs_prior", sa.Integer(), nullable=True),
        sa.Column("top_assets", sa.JSON(), nullable=True),
        sa.Column("top_tech", sa.JSON(), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bb_corpus_trends_week_starting", "bb_corpus_trends", ["week_starting"])
    op.create_index("ix_bb_corpus_trends_vuln_class", "bb_corpus_trends", ["vuln_class"])

    op.create_table(
        "bb_corpus_signatures",
        sa.Column("source_repo", sa.String(length=255), nullable=False),
        sa.Column("tag", sa.String(length=255), nullable=True),
        sa.Column("signature_blob", sa.Text(), nullable=False),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("updated_at_source", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bb_corpus_signatures_source_repo", "bb_corpus_signatures", ["source_repo"])
    op.create_index("ix_bb_corpus_signatures_tag", "bb_corpus_signatures", ["tag"])

    op.create_table(
        "corpus_ingest_log",
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("items_added", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("items_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.JSON(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_corpus_ingest_log_source_name", "corpus_ingest_log", ["source_name"])


def downgrade() -> None:
    op.drop_index("ix_corpus_ingest_log_source_name", table_name="corpus_ingest_log")
    op.drop_table("corpus_ingest_log")
    op.drop_index("ix_bb_corpus_signatures_tag", table_name="bb_corpus_signatures")
    op.drop_index("ix_bb_corpus_signatures_source_repo", table_name="bb_corpus_signatures")
    op.drop_table("bb_corpus_signatures")
    op.drop_index("ix_bb_corpus_trends_vuln_class", table_name="bb_corpus_trends")
    op.drop_index("ix_bb_corpus_trends_week_starting", table_name="bb_corpus_trends")
    op.drop_table("bb_corpus_trends")
    op.drop_index("ix_bb_corpus_advisories_severity", table_name="bb_corpus_advisories")
    op.drop_index("ix_bb_corpus_advisories_ghsa_id", table_name="bb_corpus_advisories")
    op.drop_index("ix_bb_corpus_advisories_cve_id", table_name="bb_corpus_advisories")
    op.drop_table("bb_corpus_advisories")
    op.drop_index("ix_bb_corpus_writeups_vuln_class", table_name="bb_corpus_writeups")
    op.drop_table("bb_corpus_writeups")
    op.drop_index("ix_bb_corpus_reports_platform_vuln", table_name="bb_corpus_reports")
    op.drop_index("ix_bb_corpus_reports_vuln_class", table_name="bb_corpus_reports")
    op.drop_index("ix_bb_corpus_reports_program_handle", table_name="bb_corpus_reports")
    op.drop_index("ix_bb_corpus_reports_source_platform", table_name="bb_corpus_reports")
    op.drop_table("bb_corpus_reports")
