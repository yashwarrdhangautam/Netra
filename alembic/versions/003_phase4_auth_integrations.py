"""Phase 4: Add MFA, notification preferences, and token blacklist

Revision ID: 003_phase4_auth_integrations
Revises: 002_phase2_coverage
Create Date: 2026-03-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_phase4_auth_integrations'
down_revision = '002_phase2_coverage'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema for Phase 4 features."""
    
    # ── Add MFA fields to users table ─────────────────────────────────────────
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('users', sa.Column('mfa_secret', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column(
        'backup_codes_hash',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        server_default=sa.text("'[]'::jsonb")
    ))
    
    # ── Add notification preferences to users table ───────────────────────────
    op.add_column('users', sa.Column('notify_email_critical', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('users', sa.Column('notify_email_high', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('users', sa.Column('notify_slack_critical', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('users', sa.Column('notify_slack_high', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('users', sa.Column('notify_sla_breach', sa.Boolean(), nullable=False, server_default='true'))
    
    # ── Create token_blacklist table ──────────────────────────────────────────
    op.create_table(
        'token_blacklist',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('token_jti', sa.String(length=255), nullable=False, index=True),
        sa.Column('token_type', sa.String(length=20), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_jti')
    )
    
    # ── Create index for token blacklist cleanup ──────────────────────────────
    op.create_index('ix_token_blacklist_expires_at', 'token_blacklist', ['expires_at'])
    
    # ── Add integration metadata to findings ──────────────────────────────────
    op.add_column('findings', sa.Column(
        'external_ids',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        server_default=sa.text("'{}'::jsonb"),
        comment='External integration IDs: {defectdojo: 123, jira: SEC-456}'
    ))
    
    # ── Add SLA tracking to findings ──────────────────────────────────────────
    op.add_column('findings', sa.Column('sla_due_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('findings', sa.Column('sla_breached', sa.Boolean(), nullable=False, server_default='false'))
    
    # ── Add scan statistics to scans table ────────────────────────────────────
    op.add_column('scans', sa.Column(
        'findings_summary',
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=True,
        server_default=sa.text("'{}'::jsonb"),
        comment='Findings by severity: {critical: 5, high: 10, ...}'
    ))


def downgrade() -> None:
    """Downgrade database schema (remove Phase 4 features)."""
    
    # ── Remove scan statistics ────────────────────────────────────────────────
    op.drop_column('scans', 'findings_summary')
    
    # ── Remove SLA tracking ───────────────────────────────────────────────────
    op.drop_column('findings', 'sla_breached')
    op.drop_column('findings', 'sla_due_at')
    
    # ── Remove integration metadata ───────────────────────────────────────────
    op.drop_column('findings', 'external_ids')
    
    # ── Drop token blacklist table ────────────────────────────────────────────
    op.drop_index('ix_token_blacklist_expires_at', table_name='token_blacklist')
    op.drop_table('token_blacklist')
    
    # ── Remove notification preferences ───────────────────────────────────────
    op.drop_column('users', 'notify_sla_breach')
    op.drop_column('users', 'notify_slack_high')
    op.drop_column('users', 'notify_slack_critical')
    op.drop_column('users', 'notify_email_high')
    op.drop_column('users', 'notify_email_critical')
    
    # ── Remove MFA fields ─────────────────────────────────────────────────────
    op.drop_column('users', 'backup_codes_hash')
    op.drop_column('users', 'mfa_secret')
    op.drop_column('users', 'mfa_enabled')
