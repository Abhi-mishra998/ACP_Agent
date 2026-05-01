"""
Audit Router — HTTP endpoints for the audit service.

FIX C-1 (downstream): create_log() now handles AuditWriter returning None (duplicate)
by raising HTTP 409 instead of crashing with PydanticUserError.
FIX: get_redis() now uses the shared settings.REDIS_URL constant.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from redis.asyncio import Redis
import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.config import settings
from sdk.common.db import get_db, get_tenant_id
from sdk.common.response import APIResponse
from services.audit.integrity import verify_audit_chain
from services.audit.models import AuditLog
from services.audit.schemas import (
    AuditLogCreate,
    AuditLogListResponse,
    AuditLogResponse,
    AuditLogSearch,
    AuditSummaryResponse,
)
from services.audit.writer import AuditWriter

router = APIRouter(prefix="/logs", tags=["audit"], dependencies=[Depends(verify_internal_secret)])


async def get_redis() -> AsyncGenerator[Redis, None]:
    r: Redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)  # type: ignore[arg-type]
    try:
        yield r
    finally:
        await r.aclose()


@router.post(
    "",
    response_model=APIResponse[AuditLogResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_log(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
    payload: AuditLogCreate,
) -> APIResponse[AuditLogResponse]:
    """Internal log injection endpoint."""
    log_entry = await AuditWriter.log(db, redis, payload)

    # C-1 fix: log_entry is None when it was a duplicate — return 409
    if log_entry is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate audit event (request_id+event_hash already exists)",
        )

    # Update real-time metrics
    tid = str(payload.tenant_id)
    await redis.incr(f"acp:metrics:total_calls:{tid}")
    if payload.decision == "deny":
        await redis.incr(f"acp:metrics:total_denials:{tid}")
    await redis.sadd(f"acp:metrics:active_agents:{tid}", str(payload.agent_id))

    risk_level = payload.metadata_json.get("risk_level", "low")
    await redis.incr(f"acp:metrics:risk_distribution:{tid}:{risk_level}")

    # Publish deny / high-risk events to audit events stream for ARE ingestion
    risk_score = float(payload.metadata_json.get("risk_score", 0))
    if payload.decision in ("deny", "kill", "escalate") or risk_score >= 0.7:
        import json as _json
        await redis.xadd(
            "acp:audit:events",
            {
                "data": _json.dumps({
                    "tenant_id":       tid,
                    "agent_id":        str(payload.agent_id),
                    "tool":            payload.tool or "unknown",
                    "severity":        payload.metadata_json.get("severity",
                                           "HIGH" if risk_score >= 0.8 else "MEDIUM"),
                    "risk_score":      risk_score,
                    "violation_count": payload.metadata_json.get("violation_count", 1),
                    "decision":        payload.decision,
                    "request_id":      str(payload.request_id) if payload.request_id else None,
                    "title":           payload.reason or "",
                    "source":          "audit_router",
                })
            },
            maxlen=100_000,
            approximate=True,
        )

    return APIResponse(data=AuditLogResponse.model_validate(log_entry))


from services.audit.aggregator import AuditAggregator


@router.get("/summary", response_model=APIResponse[AuditSummaryResponse])
async def get_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AuditSummaryResponse]:
    """Fast dashboard summary from Redis counters + Deep DB insights."""
    tid = str(tenant_id)

    # 1. Real-time counters from Redis
    total_calls = await redis.get(f"acp:metrics:total_calls:{tid}") or 0
    total_denials = await redis.get(f"acp:metrics:total_denials:{tid}") or 0
    agent_count = await redis.scard(f"acp:metrics:active_agents:{tid}") or 0

    total_reqs = int(total_calls)
    blocked_reqs = int(total_denials)
    allowed_reqs = total_reqs - blocked_reqs

    risk_dist = {
        "critical": int(await redis.get(f"acp:metrics:risk_distribution:{tid}:critical") or 0),
        "high": int(await redis.get(f"acp:metrics:risk_distribution:{tid}:high") or 0),
        "medium": int(await redis.get(f"acp:metrics:risk_distribution:{tid}:medium") or 0),
        "low": int(await redis.get(f"acp:metrics:risk_distribution:{tid}:low") or 0),
    }

    # 2. Deep Insights from AuditAggregator (DB)
    top_risky = await AuditAggregator.get_top_risky_agents(db, tenant_id, limit=5)
    trends = await AuditAggregator.get_anomaly_trends(db, tenant_id, days=7)

    # 3. Avg risk score from DB
    avg_risk_result = await db.execute(
        select(func.avg(
            sa.cast(AuditLog.metadata_json["risk_score"], sa.Float)
        )).where(AuditLog.tenant_id == tenant_id)
    )
    avg_risk = float(avg_risk_result.scalar_one_or_none() or 0.0)

    return APIResponse(
        data=AuditSummaryResponse(
            total_calls=total_reqs,
            total_denials=blocked_reqs,
            active_agents_count=agent_count,
            total_requests=total_reqs,
            blocked_requests=blocked_reqs,
            allowed_requests=allowed_reqs,
            threats_blocked=blocked_reqs,
            high_risk_agents=risk_dist.get("critical", 0) + risk_dist.get("high", 0),
            avg_risk_score=round(avg_risk, 4),
            requests_by_hour=[],
            risk_distribution=risk_dist,
            metadata={
                "top_risky_agents": top_risky,
                "anomaly_trends": trends,
            }
        )
    )

@router.get("/trends", response_model=APIResponse[list[dict]])
async def get_trends(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    days: int = Query(7, ge=1, le=30),
) -> APIResponse[list[dict]]:
    """Get time-series anomaly trends for UI charts."""
    trends = await AuditAggregator.get_anomaly_trends(db, tenant_id, days=days)
    return APIResponse(data=trends)


@router.get("/risk/timeline", response_model=APIResponse[list[dict]])
async def risk_timeline(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    days: int = Query(7, ge=1, le=30),
) -> APIResponse[list[dict]]:
    """Return 7-day risk timeline trends."""
    trends = await AuditAggregator.get_anomaly_trends(db, tenant_id, days=days)
    return APIResponse(data=trends)


@router.get("/risk/top-threats", response_model=APIResponse[list[dict]])
async def risk_top_threats(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    limit: int = Query(10, ge=1, le=50),
) -> APIResponse[list[dict]]:
    """Return top high-risk agents in the specified window."""
    agents = await AuditAggregator.get_top_risky_agents(db, tenant_id, limit=limit)
    return APIResponse(data=agents)


@router.get("", response_model=APIResponse[AuditLogListResponse])
async def list_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    agent_id: uuid.UUID | None = None,
    action: str | None = None,
    decision: str | None = None,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> APIResponse[AuditLogListResponse]:
    """List audit logs with filtering and pagination."""
    query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)

    if agent_id:
        query = query.where(AuditLog.agent_id == agent_id)
    if action:
        query = query.where(AuditLog.action == action)
    if decision:
        query = query.where(AuditLog.decision == decision)

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    items = result.scalars().all()

    return APIResponse(
        data=AuditLogListResponse(
            total=total,
            limit=limit,
            offset=offset,
            items=[AuditLogResponse.model_validate(item) for item in items],
        )
    )


@router.post("/search", response_model=APIResponse[AuditLogListResponse])
async def search_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    payload: AuditLogSearch,
) -> APIResponse[AuditLogListResponse]:
    """Advanced search for audit logs with date ranging and metadata filtering."""
    query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)

    if payload.agent_id:
        query = query.where(AuditLog.agent_id == payload.agent_id)
    if payload.action:
        query = query.where(AuditLog.action == payload.action)
    if payload.decision:
        query = query.where(AuditLog.decision == payload.decision)
    if payload.tool:
        query = query.where(AuditLog.tool == payload.tool)
    if payload.start_date:
        query = query.where(AuditLog.timestamp >= payload.start_date)
    if payload.end_date:
        query = query.where(AuditLog.timestamp <= payload.end_date)
    if payload.metadata_filter:
        query = query.where(AuditLog.metadata_json.contains(payload.metadata_filter))

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = (
        query.order_by(AuditLog.timestamp.desc())
        .offset(payload.offset)
        .limit(payload.limit)
    )
    result = await db.execute(query)
    items = result.scalars().all()

    return APIResponse(
        data=AuditLogListResponse(
            total=total,
            limit=payload.limit,
            offset=payload.offset,
            items=[AuditLogResponse.model_validate(item) for item in items],
        )
    )


@router.get("/soc-timeline", response_model=APIResponse[list[dict]])
async def soc_timeline(
    db:        Annotated[AsyncSession, Depends(get_db)],
    redis:     Annotated[Redis, Depends(get_redis)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    limit:     int = Query(60, ge=1, le=200),
) -> APIResponse[list[dict]]:
    """
    Aggregated SOC event feed. Merges:
    - Audit log deny/kill/escalate decisions
    - High-risk events (risk_score >= 0.7)
    Returns a unified timeline sorted newest-first.
    """
    # Fetch security-relevant audit events
    q = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .where(
            sa.or_(
                AuditLog.decision.in_(["deny", "kill", "escalate"]),
                sa.cast(AuditLog.metadata_json["risk_score"], sa.Float) >= 0.7,
            )
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()

    def _sev(row: AuditLog) -> str:
        risk = float((row.metadata_json or {}).get("risk_score", 0))
        dec  = (row.decision or "").lower()
        if dec == "kill" or risk >= 0.90:
            return "CRITICAL"
        if dec == "deny" or risk >= 0.70:
            return "HIGH"
        if risk >= 0.50:
            return "MEDIUM"
        return "LOW"

    def _type(row: AuditLog) -> str:
        dec = (row.decision or "").lower()
        if dec == "kill":       return "agent_kill"
        if dec == "escalate":   return "escalation"
        if dec == "deny":       return "policy_deny"
        return "high_risk"

    def _msg(row: AuditLog) -> str:
        dec  = (row.decision or "allow").upper()
        tool = row.tool or "unknown"
        risk = float((row.metadata_json or {}).get("risk_score", 0))
        reason = (row.reason or "")[:80]
        return f"{dec} — {tool} (risk {risk:.0%}){f': {reason}' if reason else ''}"

    tid = str(tenant_id)
    auth_failures = int(await redis.get(f"acp:metrics:total_denials:{tid}") or 0)

    events = [
        {
            "id":        str(row.id),
            "type":      _type(row),
            "severity":  _sev(row),
            "agent_id":  str(row.agent_id),
            "timestamp": row.timestamp.isoformat() if row.timestamp else "",
            "message":   _msg(row),
            "tool":      row.tool,
            "decision":  row.decision,
            "risk_score": float((row.metadata_json or {}).get("risk_score", 0)),
        }
        for row in rows
    ]

    return APIResponse(data=events)


@router.get("/verify", response_model=APIResponse[dict])
async def verify_integrity(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[dict]:
    """Perform a cryptographic integrity check on the audit log chain."""
    result = await verify_audit_chain(db, tenant_id)
    return APIResponse(data=result)
