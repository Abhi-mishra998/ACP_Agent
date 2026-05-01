from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import Depends, FastAPI

from sdk.common.auth import verify_internal_secret
from sdk.utils import setup_app
from services.behavior.service import behavior_engine

logger = structlog.get_logger(__name__)

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # behavior_engine uses a default redis client if not provided
    yield

app = FastAPI(
    title="ACP Behavior Service",
    description="Real-time behavioral intelligence and sequence analysis",
    version="1.0.0",
    lifespan=lifespan,
)

setup_app(app, "behavior")

@app.post("/analyze")
async def analyze_behavior(payload: dict, _: str = Depends(verify_internal_secret)):
    """
    Standalone endpoint for behavior analysis.
    In distributed mode, Gateway calls this via HTTP.
    """
    tenant_id = payload.get("tenant_id")
    agent_id = payload.get("agent_id")
    tool = payload.get("tool")
    tokens = payload.get("tokens", 0)

    result = await behavior_engine.record_action(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool=tool,
        tokens=tokens
    )
    return {"success": True, "data": result}

@app.post("/check")
async def check_behavior(payload: dict, _: str = Depends(verify_internal_secret)):
    """
    Check behavioral sequence for anomalies without recording (pre-flight).
    """
    result = await behavior_engine.check_behavior(
        agent_id=payload.get("agent_id"),
        tool_name=payload.get("tool_name"),
        payload_hash=payload.get("payload_hash"),
        payload_text=payload.get("payload_text"),
        tenant_id=payload.get("tenant_id")
    )
    return {"success": True, "data": result}
