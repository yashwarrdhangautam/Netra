"""Phase 2: Add SAST, CSPM, AI/LLM phase types.

Revision ID: 002
Revises: 001
Create Date: 2026-03-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: str | None = '001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add new phase types to the phasetype enum.
    
    For PostgreSQL, we use ALTER TYPE ADD VALUE.
    For SQLite, we need to recreate the table since SQLite doesn't support
    altering enum types.
    """
    # Get the database dialect
    conn = op.get_bind()
    dialect = conn.dialect.name
    
    new_phase_types = [
        'SAST',
        'SECRETS', 
        'DEPENDENCIES',
        'CSPM',
        'CONTAINER',
        'IAC',
        'AI_LLM',
    ]
    
    if dialect == 'postgresql':
        # PostgreSQL: Add new enum values
        for phase_type in new_phase_types:
            op.execute(f"ALTER TYPE phasetype ADD VALUE IF NOT EXISTS '{phase_type}'")
    
    elif dialect == 'sqlite':
        # SQLite: Recreate table with new enum values
        # First, get existing data
        result = conn.execute(sa.text("SELECT * FROM scan_phases"))
        existing_data = result.fetchall()
        
        # Drop the old table
        op.drop_table('scan_phases')
        
        # Create new table with updated enum (as TEXT with CHECK constraint)
        op.create_table(
            'scan_phases',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('scan_id', sa.String(length=36), nullable=False),
            sa.Column('phase_type', sa.Text(), nullable=False),
            sa.Column('status', sa.Text(), nullable=False),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('progress', sa.Float(), nullable=False),
            sa.Column('findings_count', sa.Integer(), nullable=False),
            sa.Column('tool_outputs', sa.JSON(), nullable=True),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
            sa.PrimaryKeyConstraint('id'),
            sa.CheckConstraint(
                "phase_type IN ('SCOPE', 'RECON_OSINT', 'RECON_SUBDOMAINS', "
                "'RECON_DISCOVERY', 'RECON_PORTS', 'VULN_SCAN', 'PENTEST', "
                "'AUTH_TEST', 'AI_ANALYSIS', 'REPORTING', 'SAST', 'SECRETS', "
                "'DEPENDENCIES', 'CSPM', 'CONTAINER', 'IAC', 'AI_LLM')",
                name='check_phase_type'
            )
        )
        
        # Restore existing data
        for row in existing_data:
            conn.execute(
                sa.text("""
                    INSERT INTO scan_phases 
                    (id, scan_id, phase_type, status, started_at, completed_at, 
                     progress, findings_count, tool_outputs, error_message)
                    VALUES (:id, :scan_id, :phase_type, :status, :started_at, 
                            :completed_at, :progress, :findings_count, :tool_outputs, :error_message)
                """),
                {
                    'id': row[0],
                    'scan_id': row[1],
                    'phase_type': row[2],
                    'status': row[3],
                    'started_at': row[4],
                    'completed_at': row[5],
                    'progress': row[6],
                    'findings_count': row[7],
                    'tool_outputs': row[8],
                    'error_message': row[9],
                }
            )


def downgrade() -> None:
    """Remove new phase types from the phasetype enum.
    
    Note: PostgreSQL doesn't support removing enum values, so this is a no-op
    for the enum itself. We can only drop the table if needed.
    """
    # For PostgreSQL, enum value removal is not supported
    # For SQLite, we could recreate the table but that's risky
    # This is intentionally a no-op for safety
    pass
