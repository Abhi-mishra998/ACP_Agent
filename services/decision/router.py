from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.config import settings
from sdk.common.db import get_db, get_tenant_id
from sdk.common.redis import get_redis_client
from sdk.common.response import APIResponse

router = APIRouter(prefix="/decision", tags=["decision"])

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

_KS_ALLOWED_ROLES = frozenset(["ADMIN", "SECURITY"])
_KILL_SWITCH_TTL = 86400 * 7  # 7 days


# ---------------------------------------------------------------------------
# REDIS (singleton-style)
# ---------------------------------------------------------------------------

_redis = None


def _get_redis():
    global _redis
    if _redis is None:
        _redis = get_redis_client(settings.REDIS_URL, decode_responses=True)
    return _redis


# ---------------------------------------------------------------------------
# SCHEMAS
# ---------------------------------------------------------------------------

class KillSwitchAction(BaseModel):
    action: Literal["engage", "disengage"]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

def _require_admin_or_security(
    x_acp_role: str | None = Header(default=None),
    _secret: str = Depends(verify_internal_secret),
) -> str:
    """
    RBAC for kill switch: requires both a valid X-Internal-Secret (proves request
    came from the Gateway after JWT validation) and ADMIN or SECURITY role injected
    by the Gateway from the validated JWT claims.
    """
    role = (x_acp_role or "").upper()
    if role not in _KS_ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Kill switch requires ADMIN or SECURITY role",
        )
    return role


# ---------------------------------------------------------------------------
# KILL SWITCH
# ---------------------------------------------------------------------------

@router.post("/kill-switch/{tenant_id}", response_model=APIResponse[dict])
async def toggle_kill_switch(
    tenant_id: str,
    payload: KillSwitchAction,
    _role: Annotated[str, Depends(_require_admin_or_security)],
) -> APIResponse[dict]:

    redis = _get_redis()
    key = f"acp:tenant_kill:{tenant_id}"

    if payload.action == "engage":
        await redis.setex(key, _KILL_SWITCH_TTL, "manual_admin_lockdown")
        return APIResponse(data={"status": "engaged", "tenant_id": tenant_id})

    await redis.delete(key)
    return APIResponse(data={"status": "disengaged", "tenant_id": tenant_id})


@router.delete("/kill-switch/{tenant_id}", response_model=APIResponse[dict])
async def disengage_kill_switch(
    tenant_id: str,
    _role: Annotated[str, Depends(_require_admin_or_security)],
) -> APIResponse[dict]:

    redis = _get_redis()
    await redis.delete(f"acp:tenant_kill:{tenant_id}")

    return APIResponse(data={"status": "disengaged", "tenant_id": tenant_id})


@router.get("/kill-switch/{tenant_id}", response_model=APIResponse[dict])
async def get_kill_switch_status(tenant_id: str) -> APIResponse[dict]:

    redis = _get_redis()
    key = f"acp:tenant_kill:{tenant_id}"

    is_engaged = await redis.exists(key)
    reason = await redis.get(key) if is_engaged else None

    return APIResponse(
        data={
            "status": "engaged" if is_engaged else "disengaged",
            "tenant_id": tenant_id,
            "reason": reason,
        }
    )


# ---------------------------------------------------------------------------
# RISK SUMMARY
# ---------------------------------------------------------------------------

def _safe_int(value) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


@router.get("/summary", response_model=APIResponse[dict])
async def get_risk_summary(
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[dict]:

    redis = _get_redis()
    tid = str(tenant_id)

    blocked = _safe_int(await redis.get(f"acp:metrics:total_denials:{tid}"))
    total = _safe_int(await redis.get(f"acp:metrics:total_calls:{tid}"))
    high_risk = _safe_int(await redis.get(f"acp:metrics:risk_distribution:{tid}:high"))
    critical_risk = _safe_int(await redis.get(f"acp:metrics:risk_distribution:{tid}:critical"))

    metrics = [
        {"time": "08:00", "score": 12},
        {"time": "12:00", "score": 24},
        {"time": "16:00", "score": high_risk * 10 or 15},
        {"time": "20:00", "score": critical_risk * 15 or 8},
        {"time": "00:00", "score": 20},
    ]

    return APIResponse(
        data={
            "threats_blocked": blocked,
            "high_risk_agents": high_risk + critical_risk,
            "total_requests": total,
            "metrics": metrics,
        }
    )


# ---------------------------------------------------------------------------
# DECISION HISTORY
# ---------------------------------------------------------------------------

@router.get("/history", response_model=APIResponse[dict])
async def get_decision_history(
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
) -> APIResponse[dict]:

    from sqlalchemy import desc, select
    from services.audit.models import AuditLog

    stmt = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
    )

    result = await db.execute(stmt)
    logs = result.scalars().all()

    return APIResponse(
        data={
            "items": [
                {
                    "id": str(log.id),
                    "agent_id": str(log.agent_id),
                    "tool": log.tool,
                    "decision": log.decision,
                    "risk_score": log.metadata_json.get("risk_score", 0.0),
                    "timestamp": log.timestamp.isoformat(),
                }
                for log in logs
            ]
        }
    )