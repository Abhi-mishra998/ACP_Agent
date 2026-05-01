from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from sdk.common.db import Base, IdMixin, OrgMixin, TenantMixin, TimestampMixin
from sdk.common.enums import AgentStatus, PermissionAction


class Agent(Base, OrgMixin, TenantMixin, IdMixin, TimestampMixin):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uix_tenant_agent_name"),
        Index("ix_agents_org_id_id", "org_id", "id"),
    )

    name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)

    description: Mapped[str] = mapped_column(String(500), nullable=False)

    owner_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)

    status: Mapped[AgentStatus] = mapped_column(
        SQLEnum(AgentStatus, name="agent_status_enum"),
        default=AgentStatus.ACTIVE,
        index=True,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(String(50), default="low", nullable=False)

    metadata_data: Mapped[dict] = mapped_column("metadata", JSONB, server_default="{}")

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    permissions: Mapped[list[AgentPermission]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class AgentPermission(Base, OrgMixin, TenantMixin, IdMixin):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("agent_id", "tool_name", name="uix_agent_tool"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    tool_name: Mapped[str] = mapped_column(
        String(150),
        index=True,
        nullable=False,
    )

    action: Mapped[PermissionAction] = mapped_column(
        SQLEnum(PermissionAction, name="permission_action_enum"),
        nullable=False,
    )

    granted_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    agent: Mapped[Agent] = relationship(back_populates="permissions")


# ---------------------------------------------------------------------------
# HARDENED INVARIANTS (SQLAlchemy Events)
# ---------------------------------------------------------------------------

from sqlalchemy import event


@event.listens_for(Agent, "before_insert")
@event.listens_for(AgentPermission, "before_insert")
def enforce_org_id_invariant(mapper, connection, target):
    """
    Enforces the SaaS strict invariant: org_id MUST equal tenant_id.
    If org_id is missing, it auto-fills from tenant_id.
    If both are present but mismatch, it raises a security error.
    """
    tenant_id = getattr(target, "tenant_id", None)
    org_id = getattr(target, "org_id", None)

    if org_id is None and tenant_id is not None:
        target.org_id = tenant_id
    elif org_id is not None and tenant_id is not None:
        if org_id != tenant_id:
            raise ValueError(
                f"SaaS Multi-tenant Violation: org_id ({org_id}) != tenant_id ({tenant_id})"
            )
