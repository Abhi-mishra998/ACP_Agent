from __future__ import annotations

from fastapi import FastAPI

from sdk.utils import setup_app
from services.learning.service import learning_engine

app = FastAPI(title="ACP Learning Service", version="1.0.0")
setup_app(app, "learning")

@app.post("/observe")
async def observe_action(payload: dict):
    return await learning_engine.observe_action(**payload)
