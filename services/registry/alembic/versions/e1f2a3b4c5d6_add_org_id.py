"""add org_id to agents and permissions

Revision ID: e1f2a3b4c5d6
Revises: d0d5347eec1b
Create Date: 2026-04-30 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'e1f2a3b4c5d6'
down_revision: str | Sequence[str] | None = 'd0d5347eec1b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Step 1: add nullable first (required for NOT NULL on existing rows)
    op.add_column('agents', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('permissions', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))

    # Step 2: backfill — org defaults to the tenant so existing rows stay valid
    op.execute("UPDATE agents SET org_id = tenant_id WHERE org_id IS NULL")
    op.execute("UPDATE permissions SET org_id = tenant_id WHERE org_id IS NULL")

    # Step 3: enforce NOT NULL
    op.alter_column('agents', 'org_id', nullable=False)
    op.alter_column('permissions', 'org_id', nullable=False)

    # Step 4: index (org_id alone + composite with id for range scans)
    op.create_index('ix_agents_org_id', 'agents', ['org_id'])
    op.create_index('ix_agents_org_id_id', 'agents', ['org_id', 'id'])
    op.create_index('ix_permissions_org_id', 'permissions', ['org_id'])


def downgrade() -> None:
    op.drop_index('ix_permissions_org_id', table_name='permissions')
    op.drop_index('ix_agents_org_id_id', table_name='agents')
    op.drop_index('ix_agents_org_id', table_name='agents')
    op.drop_column('permissions', 'org_id')
    op.drop_column('agents', 'org_id')
