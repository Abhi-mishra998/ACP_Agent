from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from sdk.common.db import Base, IdMixin, OrgMixin, TenantMixin, TimestampMixin


class AuditLog(Base, OrgMixin, TenantMixin, IdMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        index=True,
        nullable=False,
    )

    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    tool: Mapped[str] = mapped_column(String(255), index=True, nullable=True)
    decision: Mapped[str] = mapped_column(
        String(50), index=True, nullable=False
    )  # allow / deny / error
    reason: Mapped[str] = mapped_column(Text, nullable=True)

    # Stores request/response payload or context
    metadata_json: Mapped[dict] = mapped_column(JSONB, default={}, nullable=False)

    request_id: Mapped[str] = mapped_column(String(50), index=True, nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    __table_args__ = (
        UniqueConstraint("request_id", "event_hash", name="uq_audit_request_event"),
        Index("ix_audit_logs_org_id_tenant_id", "org_id", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# HARDENED INVARIANTS (SQLAlchemy Events)
# ---------------------------------------------------------------------------

from sqlalchemy import event


@event.listens_for(AuditLog, "before_insert")
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
