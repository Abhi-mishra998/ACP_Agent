"""
ACP Shared Database Layer
=========================
Single engine, session factory, and ORM mixins for the entire monorepo.
Uses sdk.common.config.settings — no per-service DatabaseSettings needed.
"""

from __future__ import annotations

import functools
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Annotated, Any

from fastapi import Header, HTTPException
from sqlalchemy import UUID, DateTime
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func

from sdk.common.config import settings


@functools.lru_cache
def get_engine() -> AsyncEngine:
    """Lazily create and cache the SQLAlchemy engine (uses shared settings)."""
    return create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        pool_size=20,       # Increased for high-load resilience
        max_overflow=10,     # Allow some bursting under stress
        connect_args={
            "server_settings": {
                "application_name": "acp-service",
                "statement_timeout": "10000",   # 10s safety kill-switch
            }
        },
    )


@functools.lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Lazily create and cache the async session factory."""
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
    )


def __getattr__(name: str) -> Any:
    """Module-level lazy attributes for backward compatibility."""
    if name == "engine":
        return get_engine()
    if name == "SessionLocal":
        return get_session_factory()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# ORM Base & Mixins
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Central declarative base class for all SQLAlchemy models."""


class IdMixin:
    """UUID primary key mixin."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )


class TimestampMixin:
    """Automatic created_at / updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class TenantMixin:
    """Strict tenant isolation column."""

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )


class OrgMixin:
    """
    Org-level isolation column — sits above tenant_id.
    One organisation can own multiple tenants (dev/staging/prod workspaces).
    Backfilled to tenant_id on existing rows by all migrations that add it.
    """

    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )


# ---------------------------------------------------------------------------
# FastAPI Dependencies
# ---------------------------------------------------------------------------


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields a scoped async DB session."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_tenant_id(x_tenant_id: Annotated[str | None, Header()] = None) -> uuid.UUID:
    """FastAPI dependency: extracts and validates X-Tenant-ID header."""
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID required")
    try:
        return uuid.UUID(x_tenant_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Tenant UUID")
