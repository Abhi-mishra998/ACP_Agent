import functools
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sdk.common.config import settings


@functools.lru_cache
def get_engine():
    """Lazily create the engine."""
    return create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)

@functools.lru_cache
def get_session_factory():
    """Lazily create the session factory."""
    return async_sessionmaker(
        get_engine(), class_=AsyncSession, expire_on_commit=False
    )

def __getattr__(name: str) -> Any:
    """Module-level getattr for lazy loading of engine and async_session."""
    if name == "engine":
        return get_engine()
    if name == "async_session":
        return get_session_factory()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


async def verify_connection() -> bool:
    """Verify database connectivity on startup."""
    try:
        from sqlalchemy import text
        engine_instance = get_engine()
        async with engine_instance.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        import structlog
        structlog.get_logger(__name__).error("database_connection_failed", error=str(e))
        return False


async def get_db_session() -> AsyncSession:
    """Dependency for getting a database session."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        return session
