from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sdk.common.config import settings
from sdk.common.db import engine, get_session_factory
from sdk.common.migrate import check_schema
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.registry.router import router
from services.registry.service import set_registry_redis


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # 1. Validate DB schema before accepting traffic
    async with get_session_factory()() as db:
        await check_schema(db, "registry")

    # 2. Initialize Redis for caching
    redis = get_redis_client(settings.REDIS_URL)
    set_registry_redis(redis)
    
    yield
    # 2. Cleanup
    await redis.aclose()
    await engine.dispose()


app = FastAPI(
    title="ACP Registry Service",
    description="Source of truth for Agent metadata and tool permissions",
    version="1.0.0",
    lifespan=lifespan,
)

# Consolidated SDK Setup
setup_app(app, "registry")

app.include_router(router)
