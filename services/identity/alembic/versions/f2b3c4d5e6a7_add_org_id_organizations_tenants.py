"""add org_id to users/credentials; create organizations and tenants tables

Revision ID: f2b3c4d5e6a7
Revises: 6acd0ad7aef5
Create Date: 2026-04-30 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'f2b3c4d5e6a7'
down_revision: str | Sequence[str] | None = '6acd0ad7aef5'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TIER_DEFAULTS = {
    "basic":      60,
    "pro":       300,
    "enterprise": 1000,
}


def upgrade() -> None:
    # ── organizations ─────────────────────────────────────────────────────────
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', name='uix_org_slug'),
    )
    op.create_index('ix_organizations_name', 'organizations', ['name'])
    op.create_index('ix_organizations_slug', 'organizations', ['slug'], unique=True)

    # ── tenants ───────────────────────────────────────────────────────────────
    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('tier', sa.Enum('basic', 'pro', 'enterprise', name='tenant_tier_enum'), nullable=False, server_default='basic'),
        sa.Column('rpm_limit', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', name='uix_tenants_tenant_id'),
    )
    op.create_index('ix_tenants_org_id', 'tenants', ['org_id'])
    op.create_index('ix_tenants_tenant_id', 'tenants', ['tenant_id'], unique=True)
    op.create_index('ix_tenants_tier', 'tenants', ['tier'])

    # ── add org_id to users ───────────────────────────────────────────────────
    op.add_column('users', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.execute("UPDATE users SET org_id = tenant_id WHERE org_id IS NULL")
    op.alter_column('users', 'org_id', nullable=False)
    op.create_index('ix_users_org_id', 'users', ['org_id'])

    # ── add org_id to agent_credentials ──────────────────────────────────────
    op.add_column('agent_credentials', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.execute("UPDATE agent_credentials SET org_id = tenant_id WHERE org_id IS NULL")
    op.alter_column('agent_credentials', 'org_id', nullable=False)
    op.create_index('ix_agent_credentials_org_id', 'agent_credentials', ['org_id'])

    # ── seed: insert the default admin tenant so lookups don't return empty ──
    # The admin user's tenant_id is the well-known 00000000-0000-0000-0000-000000000001.
    # We create a matching org + tenant row so `get_tenant_metadata` returns real data.
    default_org_id = '00000000-0000-0000-0000-000000000001'
    default_tenant_id = '00000000-0000-0000-0000-000000000001'

    op.execute(f"""
        INSERT INTO organizations (id, name, slug, is_active)
        VALUES ('{default_org_id}', 'Default Organisation', 'default', true)
        ON CONFLICT DO NOTHING
    """)
    op.execute(f"""
        INSERT INTO tenants (id, org_id, tenant_id, name, tier, rpm_limit, is_active)
        VALUES (
            gen_random_uuid(),
            '{default_org_id}',
            '{default_tenant_id}',
            'Default Tenant',
            'enterprise',
            1000,
            true
        )
        ON CONFLICT (tenant_id) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_index('ix_agent_credentials_org_id', table_name='agent_credentials')
    op.drop_column('agent_credentials', 'org_id')

    op.drop_index('ix_users_org_id', table_name='users')
    op.drop_column('users', 'org_id')

    op.drop_index('ix_tenants_tier', table_name='tenants')
    op.drop_index('ix_tenants_tenant_id', table_name='tenants')
    op.drop_index('ix_tenants_org_id', table_name='tenants')
    op.drop_table('tenants')
    op.execute("DROP TYPE IF EXISTS tenant_tier_enum")

    op.drop_index('ix_organizations_slug', table_name='organizations')
    op.drop_index('ix_organizations_name', table_name='organizations')
    op.drop_table('organizations')
