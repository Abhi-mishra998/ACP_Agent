from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from sdk.common.db import Base, IdMixin, TenantMixin, TimestampMixin


class APIKey(Base, TenantMixin, IdMixin, TimestampMixin):
    """Stores API Keys for customers/users of a Tenant."""

    __tablename__ = "api_keys"

    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # The actual key hint or prefix for display
    key_prefix: Mapped[str] = mapped_column(String(10), nullable=False)

    # Hashed version of the full API key
    key_hash: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
