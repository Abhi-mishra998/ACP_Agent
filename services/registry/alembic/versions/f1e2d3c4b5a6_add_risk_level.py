"""add risk_level to agents

Revision ID: f1e2d3c4b5a6
Revises: e1f2a3b4c5d6
Create Date: 2026-04-30 15:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f1e2d3c4b5a6'
down_revision: str | Sequence[str] | None = 'e1f2a3b4c5d6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add risk_level with a default of 'low'
    op.add_column('agents', sa.Column('risk_level', sa.String(length=50), server_default='low', nullable=False))


def downgrade() -> None:
    op.drop_column('agents', 'risk_level')
