"""enforce org_id not null on users and agent_credentials

Revision ID: e3f4a5b6c7d8
Revises: f2b3c4d5e6a7
Create Date: 2026-04-30 15:30:00.000000

"""
from collections.abc import Sequence

from alembic import op

revision: str = 'e3f4a5b6c7d8'
down_revision: str | Sequence[str] | None = 'f2b3c4d5e6a7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Backfill users
    op.execute("UPDATE users SET org_id = tenant_id WHERE org_id IS NULL")
    op.alter_column('users', 'org_id', nullable=False)
    
    # 2. Backfill agent_credentials
    op.execute("UPDATE agent_credentials SET org_id = tenant_id WHERE org_id IS NULL")
    op.alter_column('agent_credentials', 'org_id', nullable=False)


def downgrade() -> None:
    op.alter_column('agent_credentials', 'org_id', nullable=True)
    op.alter_column('users', 'org_id', nullable=True)
