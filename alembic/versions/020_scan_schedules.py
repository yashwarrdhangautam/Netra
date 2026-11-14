"""scan_schedules table for recurring and one-time scans

Revision ID: 020_scan_schedules
Revises: 019_corpus_blocklist
Create Date: 2026-11-12 00:50:00.000000

The ScanSchedule model (netra.worker.scheduler) and the /schedules API existed, but
no migration created the table, so every schedule request failed with
"relation scan_schedules does not exist". Idempotent: skips when the table exists.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "020_scan_schedules"
down_revision = "019_corpus_blocklist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "scan_schedules" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("schedule_type", sa.String(length=20), nullable=False),
        sa.Column("cron_minute", sa.String(length=100), nullable=True),
        sa.Column("cron_hour", sa.String(length=100), nullable=True),
        sa.Column("cron_day_of_week", sa.String(length=100), nullable=True),
        sa.Column("cron_day_of_month", sa.String(length=100), nullable=True),
        sa.Column("cron_month_of_year", sa.String(length=100), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("profile", sa.String(length=50), nullable=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_runs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notify_on_complete", sa.Boolean(), nullable=True),
        sa.Column("notify_on_failure", sa.Boolean(), nullable=True),
        sa.Column("notification_emails", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    if "scan_schedules" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("scan_schedules")
