"""
ACP Forensics Service
======================
Forensic replay and investigation service for the Agent Control Plane.
Reads from the audit (acp_audit) database.

Created to support /forensics/replay/{agent_id} and /forensics/investigation endpoints
proxied by the Gateway (P0-3 / P0-5 fix required this service to exist as a container).
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from sdk.common.db import engine
from sdk.utils import setup_app
from services.forensics.router import router


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield
    await engine.dispose()


app = FastAPI(
    title="ACP Forensics Service",
    description="Forensic replay and investigation for Agent Control Plane agents",
    version="1.0.0",
    lifespan=lifespan,
)

setup_app(app, "forensics")

app.include_router(router)
