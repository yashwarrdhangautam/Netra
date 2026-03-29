"""Initial schema migration for NETRA.

Revision ID: 001
Revises: 
Create Date: 2026-03-28

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial database schema."""
    # Create enums
    scan_status = sa.Enum(
        'PENDING', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED',
        name='scanstatus'
    )
    scan_status.create(op.get_bind())

    scan_profile = sa.Enum(
        'QUICK', 'STANDARD', 'DEEP', 'API_ONLY', 'CLOUD', 'MOBILE',
        'CONTAINER', 'AI_LLM', 'CUSTOM',
        name='scanprofile'
    )
    scan_profile.create(op.get_bind())

    target_type = sa.Enum(
        'DOMAIN', 'IP', 'URL', 'IP_RANGE', 'DOMAIN_LIST',
        name='targettype'
    )
    target_type.create(op.get_bind())

    severity = sa.Enum(
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
        name='severity'
    )
    severity.create(op.get_bind())

    finding_status = sa.Enum(
        'NEW', 'CONFIRMED', 'IN_PROGRESS', 'RESOLVED', 'VERIFIED',
        'FALSE_POSITIVE', 'ACCEPTED_RISK',
        name='findingstatus'
    )
    finding_status.create(op.get_bind())

    phase_type = sa.Enum(
        'SCOPE', 'RECON_OSINT', 'RECON_SUBDOMAINS', 'RECON_DISCOVERY',
        'RECON_PORTS', 'VULN_SCAN', 'PENTEST', 'AUTH_TEST',
        'AI_ANALYSIS', 'REPORTING',
        name='phasetype'
    )
    phase_type.create(op.get_bind())

    phase_status = sa.Enum(
        'PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED',
        name='phasestatus'
    )
    phase_status.create(op.get_bind())

    report_type = sa.Enum(
        'EXECUTIVE', 'TECHNICAL', 'PENTEST', 'COMPLIANCE', 'HTML',
        'EXCEL', 'EVIDENCE', 'DELTA', 'API', 'CLOUD', 'FULL',
        name='reporttype'
    )
    report_type.create(op.get_bind())

    report_status = sa.Enum(
        'PENDING', 'GENERATING', 'COMPLETED', 'FAILED',
        name='reportstatus'
    )
    report_status.create(op.get_bind())

    user_role = sa.Enum(
        'ADMIN', 'USER', 'VIEWER',
        name='userrole'
    )
    user_role.create(op.get_bind())

    # Create tables
    op.create_table(
        'targets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_type', sa.String(length=20), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('scope_includes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('scope_excludes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('metadata_', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('api_key_hash', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )

    op.create_table(
        'scans',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('profile', sa.String(length=20), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('checkpoint_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'compliance_mappings',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=True),
        sa.Column('framework', sa.String(length=50), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('control_name', sa.String(length=500), nullable=False),
        sa.Column('control_description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('is_mapped', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'credentials',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('credential_type', sa.String(length=50), nullable=False),
        sa.Column('login_url', sa.Text(), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('password_encrypted', sa.Text(), nullable=True),
        sa.Column('token', sa.Text(), nullable=True),
        sa.Column('headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('cookies', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('auth_flow', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'findings',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=100), nullable=True),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('cve_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('url', sa.Text(), nullable=True),
        sa.Column('parameter', sa.String(length=255), nullable=True),
        sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('tool_source', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('ai_analysis', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('assignee', sa.String(length=255), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('dedup_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_dedup_hash'), 'findings', ['dedup_hash'], unique=False)

    op.create_table(
        'reports',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('report_type', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'scan_diffs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_a_id', sa.Uuid(), nullable=False),
        sa.Column('scan_b_id', sa.Uuid(), nullable=False),
        sa.Column('new_findings', sa.Integer(), nullable=True),
        sa.Column('resolved_findings', sa.Integer(), nullable=True),
        sa.Column('changed_findings', sa.Integer(), nullable=True),
        sa.Column('unchanged_findings', sa.Integer(), nullable=True),
        sa.Column('diff_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_a_id'], ['scans.id'], ),
        sa.ForeignKeyConstraint(['scan_b_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'scan_phases',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('phase_type', sa.String(length=30), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('progress', sa.Float(), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=True),
        sa.Column('tool_outputs', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Drop initial database schema."""
    op.drop_table('scan_phases')
    op.drop_table('scan_diffs')
    op.drop_table('reports')
    op.drop_index(op.f('ix_findings_dedup_hash'), table_name='findings')
    op.drop_table('findings')
    op.drop_table('credentials')
    op.drop_table('compliance_mappings')
    op.drop_table('scans')
    op.drop_table('users')
    op.drop_table('targets')

    # Drop enums
    sa.Enum(name='userrole').drop(op.get_bind())
    sa.Enum(name='reportstatus').drop(op.get_bind())
    sa.Enum(name='reporttype').drop(op.get_bind())
    sa.Enum(name='phasestatus').drop(op.get_bind())
    sa.Enum(name='phasetype').drop(op.get_bind())
    sa.Enum(name='findingstatus').drop(op.get_bind())
    sa.Enum(name='severity').drop(op.get_bind())
    sa.Enum(name='targettype').drop(op.get_bind())
    sa.Enum(name='scanprofile').drop(op.get_bind())
    sa.Enum(name='scanstatus').drop(op.get_bind())
