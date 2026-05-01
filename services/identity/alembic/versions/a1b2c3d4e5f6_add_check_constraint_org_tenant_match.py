"""add check constraint for org_tenant_match

Revision ID: a1b2c3d4e5f6
Revises: e3f4a5b6c7d8
Create Date: 2026-04-30 16:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: str | Sequence[str] | None = 'e3f4a5b6c7d8'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # HARDENED: Enforce the 'Strict SaaS' invariant at the database level.
    # This prevents any bug, manual update, or raw SQL from ever creating
    # a cross-tenant org relationship.
    op.create_check_constraint(
        'ck_users_org_tenant_match',
        'users',
        sa.column('org_id') == sa.column('tenant_id')
    )
    op.create_check_constraint(
        'ck_agent_creds_org_tenant_match',
        'agent_credentials',
        sa.column('org_id') == sa.column('tenant_id')
    )


def downgrade() -> None:
    op.drop_constraint('ck_agent_creds_org_tenant_match', 'agent_credentials', type_='check')
    op.drop_constraint('ck_users_org_tenant_match', 'users', type_='check')
