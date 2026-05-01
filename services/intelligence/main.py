from __future__ import annotations

from fastapi import FastAPI

from sdk.utils import setup_app
from services.intelligence.service import intelligence_engine

app = FastAPI(title="ACP Intelligence Service", version="1.0.0")
setup_app(app, "intelligence")

@app.get("/system-intelligence/{tenant_id}")
async def get_intel(tenant_id: str):
    import uuid
    return await intelligence_engine.get_system_intelligence(uuid.UUID(tenant_id))
