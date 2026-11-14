"""Align JSON columns on jsonb, matching the models' shared JSONB type.

Some tables were created as ``json`` and others as ``jsonb``, so the live schema drifted from
the models. The cast is safe: every value is already valid JSON. Columns already on jsonb are
unchanged by the cast.

Revision ID: 022_jsonb_alignment
Revises: 021_target_client_assignment
"""

from alembic import op

revision = "022_jsonb_alignment"
down_revision = "021_target_client_assignment"
branch_labels = None
depends_on = None

# (table, column) pairs that were json when this migration was written.
JSON_COLUMNS: list[tuple[str, str]] = [
    ("audit_logs", "detail"),
    ("audit_ui_actions", "metadata_"),
    ("bb_agentic_steps", "metadata_"),
    ("bb_agentic_steps", "observations_in"),
    ("bb_agentic_steps", "observations_out"),
    ("bb_corpus_advisories", "affected_packages"),
    ("bb_corpus_advisories", "embedding"),
    ("bb_corpus_advisories", "metadata_"),
    ("bb_corpus_reports", "embedding"),
    ("bb_corpus_reports", "metadata_"),
    ("bb_corpus_reports", "tech_stack"),
    ("bb_corpus_signatures", "metadata_"),
    ("bb_corpus_trends", "metadata_"),
    ("bb_corpus_trends", "top_assets"),
    ("bb_corpus_trends", "top_tech"),
    ("bb_corpus_writeups", "embedding"),
    ("bb_corpus_writeups", "metadata_"),
    ("bb_corpus_writeups", "tech_stack"),
    ("bb_evidence", "metadata_"),
    ("bb_evidence_replays", "diff"),
    ("bb_hunt_budgets", "metadata_"),
    ("bb_hunt_plans", "json_plan"),
    ("bb_hunt_plans", "metadata_"),
    ("bb_programs", "active_classes_approved"),
    ("corpus_ingest_log", "errors"),
    ("scan_schedules", "config"),
    ("scan_schedules", "notification_emails"),
]


def upgrade() -> None:
    for table, column in JSON_COLUMNS:
        op.execute(f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE jsonb USING "{column}"::jsonb')


def downgrade() -> None:
    for table, column in JSON_COLUMNS:
        op.execute(f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE json USING "{column}"::json')
