import asyncio
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sdk.common.config import settings
from sdk.common.db import get_engine, Base
from services.identity.models import User # noqa: F401 # Ensure models are imported for metadata

# The identity service in Docker uses acp_identity. 
# We override the base DATABASE_URL to target the correct schema for these tests.
IDENTITY_TEST_DB_URL = settings.DATABASE_URL.replace("/acp", "/acp_identity")

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_db():
    """Ensure tables exist in the identity database before tests run."""
    engine = create_async_engine(IDENTITY_TEST_DB_URL)
    async with engine.begin() as conn:
        # Create all tables defined in identity models
        await conn.run_sync(Base.metadata.create_all)
    
    # Also dispose any existing cached engine to ensure loop consistency
    cached_engine = get_engine()
    await cached_engine.dispose()
    
    yield
    await engine.dispose()
    await cached_engine.dispose()

@pytest_asyncio.fixture
async def db() -> AsyncSession:
    """
    Provides a real async session for identity service tests.
    Creates a dedicated session for the test loop to avoid asyncpg loop issues.
    """
    engine = create_async_engine(IDENTITY_TEST_DB_URL)
    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()
    await engine.dispose()
