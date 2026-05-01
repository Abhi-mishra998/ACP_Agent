"""add org_id to audit_logs

Revision ID: a3b4c5d6e7f8
Revises: ef9332640e58
Create Date: 2026-04-30 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = 'a3b4c5d6e7f8'
down_revision: str | Sequence[str] | None = 'ef9332640e58'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('audit_logs', sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.execute("UPDATE audit_logs SET org_id = tenant_id WHERE org_id IS NULL")
    op.alter_column('audit_logs', 'org_id', nullable=False)
    op.create_index('ix_audit_logs_org_id', 'audit_logs', ['org_id'])
    op.create_index('ix_audit_logs_org_id_tenant_id', 'audit_logs', ['org_id', 'tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_audit_logs_org_id_tenant_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_org_id', table_name='audit_logs')
    op.drop_column('audit_logs', 'org_id')
