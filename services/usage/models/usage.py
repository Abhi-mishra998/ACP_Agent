from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from sdk.common.db import Base, IdMixin, TenantMixin


class UsageRecord(Base, TenantMixin, IdMixin):
    """Tracks billable units and costs for tool execution."""

    __tablename__ = "usage_records"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    tool: Mapped[str] = mapped_column(String(255), nullable=False)

    # Generic units (e.g. tokens, requests, computation time)
    units: Mapped[int] = mapped_column(Integer, default=1)

    # Estimated cost in credits/currency
    cost: Mapped[float] = mapped_column(Float, default=0.0)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
