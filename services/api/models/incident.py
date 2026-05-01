from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sdk.common.db import Base, IdMixin, TenantMixin, TimestampMixin


class Incident(Base, TenantMixin, IdMixin, TimestampMixin):
    """First-class security incident entity with full lifecycle management."""

    __tablename__ = "incidents"

    incident_number: Mapped[str]       = mapped_column(String(20),  unique=True, index=True, nullable=False)
    agent_id:        Mapped[str]       = mapped_column(String(36),  index=True,  nullable=False)
    severity:        Mapped[str]       = mapped_column(String(20),  nullable=False)
    status:          Mapped[str]       = mapped_column(String(30),  index=True, default="OPEN", nullable=False)
    trigger:         Mapped[str]       = mapped_column(String(50),  nullable=False)
    title:           Mapped[str]       = mapped_column(String(255), nullable=False)
    risk_score:      Mapped[float]     = mapped_column(Float,       default=0.0, nullable=False)
    tool:            Mapped[str | None]  = mapped_column(String(255), nullable=True)
    request_id:      Mapped[str | None]  = mapped_column(String(100), nullable=True, index=True)
    assigned_to:     Mapped[str | None]  = mapped_column(String(255), nullable=True)
    actions_taken:   Mapped[list]      = mapped_column(JSON, default=list, nullable=False)
    timeline:        Mapped[list]      = mapped_column(JSON, default=list, nullable=False)
    resolved_at:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # SLA timestamps (Fix 8)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mitigated_at:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Audit linkage (Fix 3)
    root_event_id:     Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    related_audit_ids: Mapped[list]       = mapped_column(JSON, default=list, nullable=False)

    # Deduplication (Fix 2)
    dedup_key:       Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    violation_count: Mapped[int]        = mapped_column(Integer, default=1, nullable=False)

    # Human-readable explanation (Fix 10)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
