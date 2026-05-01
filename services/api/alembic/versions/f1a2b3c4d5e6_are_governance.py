"""ARE governance: versioning, mode, stop_on_match, feedback

Revision ID: f1a2b3c4d5e6
Revises: e5f8a1b2c3d4
Create Date: 2026-04-25 09:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f1a2b3c4d5e6'
down_revision: str | Sequence[str] | None = 'e5f8a1b2c3d4'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('auto_response_rules', sa.Column('stop_on_match',       sa.Boolean(),  nullable=False, server_default='true'))
    op.add_column('auto_response_rules', sa.Column('mode',                sa.Text(),     nullable=False, server_default='auto'))
    op.add_column('auto_response_rules', sa.Column('version',             sa.Integer(),  nullable=False, server_default='1'))
    op.add_column('auto_response_rules', sa.Column('version_history',     sa.JSON(),     nullable=False, server_default='[]'))
    op.add_column('auto_response_rules', sa.Column('false_positive_count',sa.Integer(),  nullable=False, server_default='0'))
    op.add_column('auto_response_rules', sa.Column('suppressed_until',    sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    for col in ('suppressed_until', 'false_positive_count', 'version_history',
                'version', 'mode', 'stop_on_match'):
        op.drop_column('auto_response_rules', col)
