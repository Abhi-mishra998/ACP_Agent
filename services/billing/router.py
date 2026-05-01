from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from redis.asyncio import Redis

from sdk.common.auth import verify_internal_secret
from sdk.common.db import get_tenant_id
from sdk.common.response import APIResponse
from services.billing.value_engine import BillingValueEngine

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Router Setup
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(verify_internal_secret)],
)

# Module-level singleton (set during gateway startup)
_value_engine: BillingValueEngine | None = None


# ---------------------------------------------------------------------------
# Dependency Injection Setup
# ---------------------------------------------------------------------------

def set_billing_redis(redis: Redis) -> None:
    """
    Called during gateway lifespan startup.
    Injects Redis into BillingValueEngine.
    """
    global _value_engine
    _value_engine = BillingValueEngine(redis)


def get_billing_engine() -> BillingValueEngine:
    """
    FastAPI dependency to safely access BillingValueEngine.
    """
    if _value_engine is None:
        raise HTTPException(
            status_code=500,
            detail="Billing engine not initialized. Ensure set_billing_redis() is called."
        )
    return _value_engine


# ---------------------------------------------------------------------------
# ROUTES — SUMMARY
# ---------------------------------------------------------------------------

@router.get("/summary", response_model=APIResponse[dict])
async def get_billing_summary(
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    engine: Annotated[BillingValueEngine, Depends(get_billing_engine)],
) -> APIResponse[dict]:
    """
    Returns full billing ROI summary for the tenant.
    """
    data = await engine.get_tenant_billing_summary(str(tenant_id))  # 🔥 FIX
    return APIResponse(data=data)


@router.get("/invoices", response_model=APIResponse[dict])
async def get_billing_invoices(
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    engine: Annotated[BillingValueEngine, Depends(get_billing_engine)],
) -> APIResponse[dict]:
    """
    Temporary invoice abstraction (until real invoice store exists).
    """
    data = await engine.get_tenant_billing_summary(str(tenant_id))  # 🔥 FIX

    invoice = {
        "invoices": [
            {
                "period": datetime.now(tz=UTC).strftime("%Y-%m"),
                "total_saved_usd": data.get("total_money_saved", 0),
                "threats_blocked": data.get("attacks_blocked", 0),
                "status": "generated",
            }
        ],
        "tenant_id": str(tenant_id),
    }

    return APIResponse(data=invoice)


# ---------------------------------------------------------------------------
# EVENTS — BILLING TRIGGERS
# ---------------------------------------------------------------------------

class BillingEvent(BaseModel):
    tenant_id: uuid.UUID
    action: str
    agent_id: uuid.UUID | None = None


@router.post("/events", response_model=APIResponse[dict])
async def record_billing_event(
    event: BillingEvent,
    engine: Annotated[BillingValueEngine, Depends(get_billing_engine)],
) -> APIResponse[dict]:
    """
    Records a protection event and calculates money saved.

    CRITICAL FIX:
    - Convert UUID → string BEFORE passing to engine
    """

    try:
        saved = await engine.record_protection_event(
            tenant_id=str(event.tenant_id),
            action=event.action,
            agent_id=str(event.agent_id) if event.agent_id else None,
        )

        logger.info(
            "billing_event_recorded",
            tenant_id=str(event.tenant_id),
            agent_id=str(event.agent_id) if event.agent_id else None,
            action=event.action,
            saved_usd=saved,
        )

        return APIResponse(data={"saved_usd": saved})

    except Exception as e:
        logger.error(
            "billing_event_failed",
            tenant_id=str(event.tenant_id),
            action=event.action,
            error=str(e),
        )
        raise HTTPException(
            status_code=500,
            detail=f"Billing event processing failed: {str(e)}"
        )