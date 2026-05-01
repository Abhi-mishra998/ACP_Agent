from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sdk.common.db import engine, get_session_factory
from sdk.common.migrate import check_schema
from sdk.utils import setup_app
from services.identity.router import router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    async with get_session_factory()() as db:
        await check_schema(db, "identity")
    yield
    await engine.dispose()


app = FastAPI(
    title="ACP Identity Service",
    description="JWT authentication + Redis-backed token lifecycle management",
    version="1.0.0",
    lifespan=lifespan,
)

# Consolidated SDK Setup
setup_app(app, "identity")

app.include_router(router)
