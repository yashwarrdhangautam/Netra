"""Phase 5: NETRA-BB bug bounty module — programs, scope rules, assets, submissions, dedup.

Revision ID: 004_bugbounty_module
Revises: 003_phase4_auth_integrations
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "004_bugbounty_module"
down_revision = "003_phase4_auth_integrations"
branch_labels = None
depends_on = None


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _json_type() -> sa.types.TypeEngine:
    if _is_postgres():
        return postgresql.JSONB(astext_type=sa.Text())
    return sa.JSON()


def _json_default(kind: str):
    if kind == "array":
        return sa.text("'[]'::jsonb") if _is_postgres() else sa.text("'[]'")
    return sa.text("'{}'::jsonb") if _is_postgres() else sa.text("'{}'")


def upgrade() -> None:
    """Create bug bounty tables: programs, scope rules, assets, submissions, dedup signatures."""

    # ── bb_programs ──────────────────────────────────────────────────────────
    op.create_table(
        "bb_programs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("platform", sa.String(length=20), nullable=False, comment="hackerone | bugcrowd | intigriti | yeswehack | private"),
        sa.Column("handle", sa.String(length=120), nullable=False, comment="Platform handle, e.g. 'shopify'"),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("policy_url", sa.String(length=512), nullable=True),
        sa.Column("payout_min", sa.Integer(), nullable=True),
        sa.Column("payout_max", sa.Integer(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="USD"),
        sa.Column("scope_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("metadata_", _json_type(), nullable=True, server_default=_json_default("object")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("platform", "handle", name="uq_bb_programs_platform_handle"),
    )
    op.create_index("ix_bb_programs_active", "bb_programs", ["active"])
    op.create_index("ix_bb_programs_platform", "bb_programs", ["platform"])

    # ── bb_scope_rules ───────────────────────────────────────────────────────
    op.create_table(
        "bb_scope_rules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("program_id", sa.UUID(), nullable=False),
        sa.Column("rule_type", sa.String(length=10), nullable=False, comment="in | out"),
        sa.Column("asset_type", sa.String(length=20), nullable=False, comment="domain|wildcard|ip|cidr|url|mobile|repo|other"),
        sa.Column("pattern", sa.String(length=512), nullable=False),
        sa.Column("severity_cap", sa.String(length=20), nullable=True, comment="critical|high|medium|low|info — caps reportable severity"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("synced_from_platform", sa.Boolean(), nullable=False, server_default="true"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["program_id"], ["bb_programs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_bb_scope_rules_program_id", "bb_scope_rules", ["program_id"])
    op.create_index("ix_bb_scope_rules_rule_type", "bb_scope_rules", ["rule_type"])

    # ── bb_assets ────────────────────────────────────────────────────────────
    op.create_table(
        "bb_assets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("program_id", sa.UUID(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("ports", _json_type(), nullable=True, server_default=_json_default("array")),
        sa.Column("tech", _json_type(), nullable=True, server_default=_json_default("array")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("metadata_", _json_type(), nullable=True, server_default=_json_default("object")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["program_id"], ["bb_programs.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("program_id", "host", name="uq_bb_assets_program_host"),
    )
    op.create_index("ix_bb_assets_program_id", "bb_assets", ["program_id"])
    op.create_index("ix_bb_assets_host", "bb_assets", ["host"])

    # ── bb_submissions ───────────────────────────────────────────────────────
    op.create_table(
        "bb_submissions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("program_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="draft",
                  comment="draft|ready_to_send|sent|acknowledged|triaging|resolved_paid|resolved_dup|resolved_na|resolved_informative"),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("draft_md", sa.Text(), nullable=True, comment="H1-style markdown body"),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_vector", sa.String(length=120), nullable=True),
        sa.Column("payout_expected", sa.Integer(), nullable=True),
        sa.Column("payout_actual", sa.Integer(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="USD"),
        sa.Column("platform_report_id", sa.String(length=64), nullable=True, comment="ID returned by H1/Bugcrowd after submission"),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verdict_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verdict_notes", sa.Text(), nullable=True),
        sa.Column("metadata_", _json_type(), nullable=True, server_default=_json_default("object")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["program_id"], ["bb_programs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_bb_submissions_program_id", "bb_submissions", ["program_id"])
    op.create_index("ix_bb_submissions_status", "bb_submissions", ["status"])

    # ── bb_dedup_signatures ──────────────────────────────────────────────────
    op.create_table(
        "bb_dedup_signatures",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("program_id", sa.UUID(), nullable=False),
        sa.Column("signature_hash", sa.String(length=64), nullable=False, comment="sha256 of (vuln_class | normalised_path | param_name)"),
        sa.Column("asset_path", sa.String(length=1024), nullable=False),
        sa.Column("signal_type", sa.String(length=40), nullable=False, comment="xss|sqli|ssrf|idor|rce|info_disc|csrf|...etc"),
        sa.Column("vuln_class", sa.String(length=80), nullable=False),
        sa.Column("metadata_", _json_type(), nullable=True, server_default=_json_default("object")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["program_id"], ["bb_programs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_bb_dedup_signatures_hash", "bb_dedup_signatures", ["signature_hash"])
    op.create_index("ix_bb_dedup_signatures_program_id", "bb_dedup_signatures", ["program_id"])
    op.create_index(
        "ix_bb_dedup_signatures_program_hash",
        "bb_dedup_signatures",
        ["program_id", "signature_hash"],
    )


def downgrade() -> None:
    """Drop bug bounty tables in reverse FK order."""
    op.drop_index("ix_bb_dedup_signatures_program_hash", table_name="bb_dedup_signatures")
    op.drop_index("ix_bb_dedup_signatures_program_id", table_name="bb_dedup_signatures")
    op.drop_index("ix_bb_dedup_signatures_hash", table_name="bb_dedup_signatures")
    op.drop_table("bb_dedup_signatures")

    op.drop_index("ix_bb_submissions_status", table_name="bb_submissions")
    op.drop_index("ix_bb_submissions_program_id", table_name="bb_submissions")
    op.drop_table("bb_submissions")

    op.drop_index("ix_bb_assets_host", table_name="bb_assets")
    op.drop_index("ix_bb_assets_program_id", table_name="bb_assets")
    op.drop_table("bb_assets")

    op.drop_index("ix_bb_scope_rules_rule_type", table_name="bb_scope_rules")
    op.drop_index("ix_bb_scope_rules_program_id", table_name="bb_scope_rules")
    op.drop_table("bb_scope_rules")

    op.drop_index("ix_bb_programs_platform", table_name="bb_programs")
    op.drop_index("ix_bb_programs_active", table_name="bb_programs")
    op.drop_table("bb_programs")
