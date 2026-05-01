"""incident sla dedup audit linkage

Revision ID: d4f7a3b2c891
Revises: c2b8e4a19f3d
Create Date: 2026-04-24 12:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'd4f7a3b2c891'
down_revision: str | Sequence[str] | None = 'c2b8e4a19f3d'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('incidents', sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('mitigated_at',    sa.DateTime(timezone=True), nullable=True))
    op.add_column('incidents', sa.Column('root_event_id',   sa.String(length=100),      nullable=True))
    op.add_column('incidents', sa.Column('related_audit_ids', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('incidents', sa.Column('dedup_key',       sa.String(length=64),       nullable=True))
    op.add_column('incidents', sa.Column('violation_count', sa.Integer(),               nullable=False, server_default='1'))
    op.add_column('incidents', sa.Column('explanation',     sa.Text(),                  nullable=True))
    op.create_index('ix_incidents_dedup_key',    'incidents', ['dedup_key'])
    op.create_index('ix_incidents_root_event_id','incidents', ['root_event_id'])


def downgrade() -> None:
    op.drop_index('ix_incidents_root_event_id', table_name='incidents')
    op.drop_index('ix_incidents_dedup_key',     table_name='incidents')
    op.drop_column('incidents', 'explanation')
    op.drop_column('incidents', 'violation_count')
    op.drop_column('incidents', 'dedup_key')
    op.drop_column('incidents', 'related_audit_ids')
    op.drop_column('incidents', 'root_event_id')
    op.drop_column('incidents', 'mitigated_at')
    op.drop_column('incidents', 'acknowledged_at')
