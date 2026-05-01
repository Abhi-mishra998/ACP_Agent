"""add incidents table

Revision ID: c2b8e4a19f3d
Revises: 81a0f934c016
Create Date: 2026-04-24 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'c2b8e4a19f3d'
down_revision: str | Sequence[str] | None = '81a0f934c016'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'incidents',
        sa.Column('id',              sa.UUID(),              nullable=False),
        sa.Column('tenant_id',       sa.UUID(),              nullable=False),
        sa.Column('incident_number', sa.String(length=20),  nullable=False),
        sa.Column('agent_id',        sa.String(length=36),  nullable=False),
        sa.Column('severity',        sa.String(length=20),  nullable=False),
        sa.Column('status',          sa.String(length=30),  nullable=False, server_default='OPEN'),
        sa.Column('trigger',         sa.String(length=50),  nullable=False),
        sa.Column('title',           sa.String(length=255), nullable=False),
        sa.Column('risk_score',      sa.Float(),            nullable=False, server_default='0'),
        sa.Column('tool',            sa.String(length=255), nullable=True),
        sa.Column('request_id',      sa.String(length=100), nullable=True),
        sa.Column('assigned_to',     sa.String(length=255), nullable=True),
        sa.Column('actions_taken',   sa.JSON(),             nullable=False, server_default='[]'),
        sa.Column('timeline',        sa.JSON(),             nullable=False, server_default='[]'),
        sa.Column('resolved_at',     sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at',      sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at',      sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_number', name='uq_incident_number'),
    )
    op.create_index('ix_incidents_tenant_id',       'incidents', ['tenant_id'])
    op.create_index('ix_incidents_agent_id',        'incidents', ['agent_id'])
    op.create_index('ix_incidents_status',          'incidents', ['status'])
    op.create_index('ix_incidents_severity',        'incidents', ['severity'])
    op.create_index('ix_incidents_incident_number', 'incidents', ['incident_number'], unique=True)
    op.create_index('ix_incidents_request_id',      'incidents', ['request_id'])
    op.create_index('ix_incidents_created_at',      'incidents', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_incidents_created_at',      table_name='incidents')
    op.drop_index('ix_incidents_request_id',      table_name='incidents')
    op.drop_index('ix_incidents_incident_number', table_name='incidents')
    op.drop_index('ix_incidents_severity',        table_name='incidents')
    op.drop_index('ix_incidents_status',          table_name='incidents')
    op.drop_index('ix_incidents_agent_id',        table_name='incidents')
    op.drop_index('ix_incidents_tenant_id',       table_name='incidents')
    op.drop_table('incidents')
