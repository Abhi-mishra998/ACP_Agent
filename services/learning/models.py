from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from sdk.common.db import Base, IdMixin, TenantMixin


class BehaviorProfileModel(Base, IdMixin, TenantMixin):
    __tablename__ = "behavior_profiles"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        postgresql.UUID(as_uuid=True), nullable=False, unique=True, index=True
    )

    # Distributions and Matrices stored as JSONB
    tool_usage_distribution: Mapped[dict] = mapped_column(
        postgresql.JSONB, server_default="{}", nullable=False
    )

    transition_matrix: Mapped[dict] = mapped_column(
        postgresql.JSONB, server_default="{}", nullable=False
    )

    avg_velocity: Mapped[float] = mapped_column(sa.Float, default=0.0, nullable=False)
    baseline_risk: Mapped[float] = mapped_column(sa.Float, default=0.0, nullable=False)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    last_updated: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )
