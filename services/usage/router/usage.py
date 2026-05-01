from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.db import get_db, get_tenant_id
from sdk.common.response import APIResponse
from services.usage.repository.usage import UsageRepository
from services.usage.schemas.usage import UsageCreate, UsageResponse, UsageSummary

# NOTE: /usage/billing/invoices is served by billing_router mounted at /usage prefix
# in usage/main.py — do not duplicate it here.

router = APIRouter(prefix="/usage", tags=["usage"], dependencies=[Depends(verify_internal_secret)])


@router.post(
    "/record",
    response_model=APIResponse[UsageResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Record tool usage event",
)
async def record_usage(
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: UsageCreate,
) -> APIResponse[UsageResponse]:
    """Internal endpoint to record a billable event."""
    repo = UsageRepository(db)
    record = await repo.record(payload)
    return APIResponse(data=UsageResponse.model_validate(record))


@router.get(
    "/summary",
    response_model=APIResponse[UsageSummary],
    summary="Get billing summary for the tenant",
)
async def get_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[UsageSummary]:
    """Returns aggregated usage and cost summary for the current tenant."""
    repo = UsageRepository(db)
    summary = await repo.get_summary(tenant_id)
    return APIResponse(data=summary)


@router.get(
    "/history",
    response_model=APIResponse[list[UsageResponse]],
    summary="Get detailed usage history",
)
async def get_history(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    limit: int = 50,
) -> APIResponse[list[UsageResponse]]:
    """Returns the most recent usage records for the current tenant."""
    repo = UsageRepository(db)
    records = await repo.list_for_tenant(tenant_id, limit=limit)
    return APIResponse(data=[UsageResponse.model_validate(r) for r in records])


