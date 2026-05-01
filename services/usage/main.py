from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sdk.common.config import settings
from sdk.common.db import engine, get_session_factory
from sdk.common.migrate import check_schema
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.billing.router import router as billing_router
from services.billing.router import set_billing_redis
from services.usage.router.usage import router as usage_router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    async with get_session_factory()() as db:
        await check_schema(db, "usage")
    redis = get_redis_client(settings.REDIS_URL, decode_responses=False)
    set_billing_redis(redis)
    yield
    await redis.aclose()
    await engine.dispose()


app = FastAPI(
    title="ACP Usage Tracking Service",
    description="Scalable usage and billing tracking for AI agent operations",
    version="1.0.0",
    lifespan=lifespan,
)

# Consolidated SDK Setup
setup_app(app, "usage")

# All telemetry routes must live under /usage for Gateway consistency
app.include_router(usage_router)

# billing_router has prefix="/billing"; mount directly to match Gateway calls
app.include_router(billing_router)
