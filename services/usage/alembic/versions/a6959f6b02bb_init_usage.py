"""init usage

Revision ID: a6959f6b02bb
Revises:
Create Date: 2026-04-17 16:58:42.133156

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a6959f6b02bb'
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('usage_records',
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('agent_id', sa.UUID(), nullable=False),
        sa.Column('tool', sa.String(length=255), nullable=False),
        sa.Column('units', sa.Integer(), nullable=False),
        sa.Column('cost', sa.Float(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_usage_records_tenant_id'), 'usage_records', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_usage_records_agent_id'), 'usage_records', ['agent_id'], unique=False)
    op.create_index(op.f('ix_usage_records_timestamp'), 'usage_records', ['timestamp'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_usage_records_timestamp'), table_name='usage_records')
    op.drop_index(op.f('ix_usage_records_agent_id'), table_name='usage_records')
    op.drop_index(op.f('ix_usage_records_tenant_id'), table_name='usage_records')
    op.drop_table('usage_records')
