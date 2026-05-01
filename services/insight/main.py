import json

import structlog
from fastapi import FastAPI, HTTPException, Depends

from sdk.common.config import settings
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from sdk.common.auth import verify_internal_secret

logger = structlog.get_logger(__name__)

redis = get_redis_client(settings.REDIS_URL, decode_responses=False)

_TIMELINE_KEY_PREFIX = "acp:groq:insights:timeline"  # per-tenant: {prefix}:{tenant_id}

app = FastAPI(
    title="ACP Groq Insight Service",
    description="AI-powered threat explanation and recommendations API",
    version="1.0.0",
)

setup_app(app, "insight")


@app.get("/insights/{event_id}", dependencies=[Depends(verify_internal_secret)])
async def get_insight(event_id: str):
    data = await redis.get(f"acp:groq:insight:{event_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Insight not found")
    return json.loads(data)


@app.get("/insights", dependencies=[Depends(verify_internal_secret)])
async def list_recent_insights(limit: int = 20, tenant_id: str = ""):
    """
    Return the most recent AI-generated threat insights, newest first.
    Scoped to tenant when X-Tenant-ID is provided via query param or header.

    Primary path: sorted set acp:groq:insights:timeline:{tenant_id} (O(log N) range query).
    Fallback path: SCAN when the sorted set is absent (e.g. fresh deployment).
    """
    insights = []
    _TIMELINE_KEY = f"{_TIMELINE_KEY_PREFIX}:{tenant_id}" if tenant_id else _TIMELINE_KEY_PREFIX

    # Primary: sorted set gives us chronological order cheaply
    if await redis.exists(_TIMELINE_KEY):
        # ZREVRANGE returns newest-first (highest score = most recent timestamp)
        event_ids = await redis.zrevrange(_TIMELINE_KEY, 0, limit - 1)
        for raw_id in event_ids:
            event_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
            raw = await redis.get(f"acp:groq:insight:{event_id}")
            if raw:
                try:
                    item = json.loads(raw)
                    item.setdefault("event_id", event_id)
                    insights.append(item)
                except Exception:
                    pass
        if insights:
            return {"success": True, "data": insights}

    # Fallback: SCAN (no ordering guarantee, used only before first worker run)
    cursor = 0
    while len(insights) < limit:
        cursor, keys = await redis.scan(cursor, match="acp:groq:insight:*", count=50)
        for k in keys:
            raw = await redis.get(k)
            if raw:
                try:
                    parsed = json.loads(raw)
                    event_id = (k.decode() if isinstance(k, bytes) else k).split(":")[-1]
                    parsed.setdefault("event_id", event_id)
                    insights.append(parsed)
                    if len(insights) >= limit:
                        break
                except Exception:
                    pass
        if cursor == 0:
            break

    return {"success": True, "data": insights}
