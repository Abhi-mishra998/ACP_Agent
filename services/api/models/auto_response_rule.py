from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column

from sdk.common.db import Base, IdMixin, TenantMixin, TimestampMixin


class AutoResponseRule(Base, TenantMixin, IdMixin, TimestampMixin):
    """Autonomous Response Engine rule — deterministic auto-mitigation policy."""

    __tablename__ = "auto_response_rules"

    name:                  Mapped[str]             = mapped_column(Text,    nullable=False)
    is_active:             Mapped[bool]            = mapped_column(Boolean, default=True,  nullable=False)
    priority:              Mapped[int]             = mapped_column(Integer, default=0,     nullable=False, index=True)
    conditions:            Mapped[dict]            = mapped_column(JSON,    nullable=False, default=dict)
    actions:               Mapped[list]            = mapped_column(JSON,    nullable=False, default=list)
    cooldown_seconds:      Mapped[int]             = mapped_column(Integer, default=300,   nullable=False)
    max_triggers_per_hour: Mapped[int]             = mapped_column(Integer, default=10,    nullable=False)
    trigger_count:         Mapped[int]             = mapped_column(Integer, default=0,     nullable=False)
    last_triggered_at:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Conflict resolution
    stop_on_match: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Action approval mode: "auto" | "manual" | "suggest"
    mode: Mapped[str] = mapped_column(Text, default="auto", nullable=False)

    # Versioning for SOC2/audit trail
    version:         Mapped[int]  = mapped_column(Integer, default=1,  nullable=False)
    version_history: Mapped[list] = mapped_column(JSON,    default=list, nullable=False)

    # Feedback / false-positive suppression
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suppressed_until:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
