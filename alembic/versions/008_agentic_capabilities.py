"""agentic capability persistence

Revision ID: 008_agentic_capabilities
Revises: 007
Create Date: 2026-05-10 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "008_agentic_capabilities"
down_revision = "007_scan_user_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "bb_programs",
        sa.Column("active_classes_approved", sa.JSON(), nullable=True),
    )
    op.create_table(
        "bb_hunt_budgets",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("max_tools", sa.Integer(), nullable=False),
        sa.Column("wallclock_minutes", sa.Integer(), nullable=False),
        sa.Column("per_tool_concurrency", sa.Integer(), nullable=False),
        sa.Column("tools_used", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_table(
        "bb_hunt_plans",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("json_plan", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_table(
        "bb_agentic_steps",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("plan_id", sa.Uuid(), nullable=True),
        sa.Column("step_n", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("tool_chosen", sa.String(length=80), nullable=True),
        sa.Column("llm_prompt", sa.Text(), nullable=True),
        sa.Column("llm_response", sa.Text(), nullable=True),
        sa.Column("observations_in", sa.JSON(), nullable=True),
        sa.Column("observations_out", sa.JSON(), nullable=True),
        sa.Column("decision_rationale", sa.Text(), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["bb_hunt_plans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("bb_agentic_steps")
    op.drop_table("bb_hunt_plans")
    op.drop_table("bb_hunt_budgets")
    op.drop_column("bb_programs", "active_classes_approved")
