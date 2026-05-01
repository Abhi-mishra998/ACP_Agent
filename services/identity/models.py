from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from sdk.common.db import Base, IdMixin, OrgMixin, TenantMixin, TimestampMixin


# =========================
# ENUMS
# =========================


class CredentialStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class UserRole(StrEnum):
    ADMIN = "ADMIN"
    SECURITY = "SECURITY"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"
    AGENT = "AGENT"


class TenantTier(StrEnum):
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# =========================
# MODELS
# =========================


class Organization(Base, IdMixin, TimestampMixin):
    """
    Top-level org entity. One org owns one or more tenants.
    Created implicitly when the first admin user registers.
    """

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Tenant(Base, OrgMixin, IdMixin, TimestampMixin):
    """
    Tenant = workspace within an org (e.g. dev / staging / prod).
    Rate limits and tier are enforced at this level.
    """

    __tablename__ = "tenants"

    # tenant_id here IS the ACP tenant_id used in all other tables
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    tier: Mapped[TenantTier] = mapped_column(
        SQLEnum(TenantTier, name="tenant_tier_enum", values_callable=lambda obj: [e.value for e in obj]),
        default=TenantTier.BASIC,
        nullable=False,
        index=True,
    )

    # Requests per minute — 0 means use tier defaults
    rpm_limit: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class AgentCredential(Base, OrgMixin, TenantMixin, IdMixin, TimestampMixin):
    """Stores hashed secrets + status for agent authentication."""

    __tablename__ = "agent_credentials"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
    )

    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[CredentialStatus] = mapped_column(
        SQLEnum(CredentialStatus, name="credential_status_enum"),
        default=CredentialStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class User(Base, OrgMixin, TenantMixin, IdMixin, TimestampMixin):
    """Represents a human administrator or viewer of the ACP Dashboard."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)

    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, name="user_role_enum"),
        default=UserRole.VIEWER,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    last_login: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

# ---------------------------------------------------------------------------
# HARDENED INVARIANTS (SQLAlchemy Events)
# ---------------------------------------------------------------------------

from sqlalchemy import event

@event.listens_for(User, "before_insert")
@event.listens_for(AgentCredential, "before_insert")
@event.listens_for(Tenant, "before_insert")
def enforce_org_id_invariant(mapper, connection, target):
    """
    Final defensive check before flush:
    If org_id is missing, it MUST default to tenant_id.
    """
    if hasattr(target, "org_id") and getattr(target, "org_id") is None:
        if hasattr(target, "tenant_id") and getattr(target, "tenant_id") is not None:
            target.org_id = target.tenant_id
        elif isinstance(target, Tenant):
            # For Tenant model, org_id must match its own tenant_id
            target.org_id = target.tenant_id
