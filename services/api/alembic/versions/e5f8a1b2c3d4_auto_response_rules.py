"""autonomous response engine rules table

Revision ID: e5f8a1b2c3d4
Revises: d4f7a3b2c891
Create Date: 2026-04-24 18:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e5f8a1b2c3d4'
down_revision: str | Sequence[str] | None = 'd4f7a3b2c891'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'auto_response_rules',
        sa.Column('id',                    sa.UUID(as_uuid=True),         nullable=False),
        sa.Column('tenant_id',             sa.UUID(as_uuid=True),         nullable=False),
        sa.Column('name',                  sa.Text(),                     nullable=False),
        sa.Column('is_active',             sa.Boolean(),                  nullable=False, server_default='true'),
        sa.Column('priority',              sa.Integer(),                  nullable=False, server_default='0'),
        sa.Column('conditions',            sa.JSON(),                     nullable=False, server_default='{}'),
        sa.Column('actions',               sa.JSON(),                     nullable=False, server_default='[]'),
        sa.Column('cooldown_seconds',      sa.Integer(),                  nullable=False, server_default='300'),
        sa.Column('max_triggers_per_hour', sa.Integer(),                  nullable=False, server_default='10'),
        sa.Column('trigger_count',         sa.Integer(),                  nullable=False, server_default='0'),
        sa.Column('last_triggered_at',     sa.DateTime(timezone=True),    nullable=True),
        sa.Column('created_at',            sa.DateTime(timezone=True),    nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at',            sa.DateTime(timezone=True),    nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_auto_response_rules_tenant_id', 'auto_response_rules', ['tenant_id'])
    op.create_index('ix_auto_response_rules_priority',  'auto_response_rules', ['priority'])
    op.create_index('ix_auto_response_rules_is_active', 'auto_response_rules', ['is_active'])


def downgrade() -> None:
    op.drop_index('ix_auto_response_rules_is_active', table_name='auto_response_rules')
    op.drop_index('ix_auto_response_rules_priority',  table_name='auto_response_rules')
    op.drop_index('ix_auto_response_rules_tenant_id', table_name='auto_response_rules')
    op.drop_table('auto_response_rules')
