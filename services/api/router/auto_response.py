from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.db import get_db, get_tenant_id
from sdk.common.response import APIResponse
from services.api.are_worker import _check_condition
from services.api.models.incident import Incident
from services.api.repository.auto_response_rule import AutoResponseRuleRepository
from services.api.schemas.auto_response_rule import (
    ARESimulateMatchItem,
    ARESimulateRequest,
    ARESimulateResponse,
    AREToggleRequest,
    AREToggleResponse,
    ApprovalRequest,
    AutoResponseRuleCreate,
    AutoResponseRuleResponse,
    AutoResponseRuleUpdate,
    FeedbackRequest,
    FeedbackResponse,
)

logger = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/auto-response",
    tags=["ARE"],
    dependencies=[Depends(verify_internal_secret)],
)

_TIME_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}

_ADMIN_ROLES = {"ADMIN", "SUPER_ADMIN", "SYSTEM"}


def _require_admin(request: Request) -> str:
    """RBAC guard: only ADMIN+ roles may create/delete/toggle ARE rules."""
    role = (request.headers.get("X-ACP-Role") or "").upper()
    if role not in _ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not permitted to manage ARE rules (requires ADMIN+)",
        )
    return role


def _redis(request: Request):
    return request.app.state.incident_redis


# ─────────────────────────────────────────────────────────────────────────────
# CRUD
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/rules", response_model=APIResponse[AutoResponseRuleResponse], status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload:   AutoResponseRuleCreate,
    request:   Request,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AutoResponseRuleResponse]:
    _require_admin(request)
    rule = await AutoResponseRuleRepository(db).create(tenant_id, payload)
    return APIResponse(data=AutoResponseRuleResponse.model_validate(rule))


@router.get("/rules", response_model=APIResponse[list[AutoResponseRuleResponse]])
async def list_rules(
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[list[AutoResponseRuleResponse]]:
    rules = await AutoResponseRuleRepository(db).list(tenant_id)
    return APIResponse(data=[AutoResponseRuleResponse.model_validate(r) for r in rules])


@router.get("/rules/{rule_id}", response_model=APIResponse[AutoResponseRuleResponse])
async def get_rule(
    rule_id:   uuid.UUID,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AutoResponseRuleResponse]:
    rule = await AutoResponseRuleRepository(db).get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return APIResponse(data=AutoResponseRuleResponse.model_validate(rule))


@router.patch("/rules/{rule_id}", response_model=APIResponse[AutoResponseRuleResponse])
async def update_rule(
    rule_id:   uuid.UUID,
    payload:   AutoResponseRuleUpdate,
    request:   Request,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AutoResponseRuleResponse]:
    repo = AutoResponseRuleRepository(db)
    rule = await repo.get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    changed_by = request.headers.get("X-ACP-Role", "api")
    rule = await repo.update(rule, payload, changed_by=changed_by)
    return APIResponse(data=AutoResponseRuleResponse.model_validate(rule))


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id:   uuid.UUID,
    request:   Request,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> None:
    _require_admin(request)
    repo = AutoResponseRuleRepository(db)
    rule = await repo.get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await repo.delete(rule)


# ─────────────────────────────────────────────────────────────────────────────
# Version history + rollback
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rules/{rule_id}/history", response_model=APIResponse[list[dict]])
async def rule_history(
    rule_id:   uuid.UUID,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[list[dict]]:
    rule = await AutoResponseRuleRepository(db).get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return APIResponse(data=list(reversed(rule.version_history or [])))


@router.post("/rules/{rule_id}/rollback/{version}", response_model=APIResponse[AutoResponseRuleResponse])
async def rollback_rule(
    rule_id:   uuid.UUID,
    version:   int,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AutoResponseRuleResponse]:
    repo = AutoResponseRuleRepository(db)
    rule = await repo.get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        rule = await repo.rollback(rule, version)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return APIResponse(data=AutoResponseRuleResponse.model_validate(rule))


# ─────────────────────────────────────────────────────────────────────────────
# Global toggle
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/toggle", response_model=APIResponse[AREToggleResponse])
async def toggle_are(
    payload:   AREToggleRequest,
    request:   Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    _role:     str = Depends(_require_admin),
) -> APIResponse[AREToggleResponse]:
    r   = _redis(request)
    tid = str(tenant_id)
    if payload.enabled:
        await r.delete(f"acp:{tid}:are:enabled")
    else:
        await r.set(f"acp:{tid}:are:enabled", "0")
    return APIResponse(data=AREToggleResponse(tenant_id=tid, enabled=payload.enabled))


@router.get("/toggle", response_model=APIResponse[AREToggleResponse])
async def get_are_status(
    request:   Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[AREToggleResponse]:
    r   = _redis(request)
    tid = str(tenant_id)
    val = await r.get(f"acp:{tid}:are:enabled")
    return APIResponse(data=AREToggleResponse(tenant_id=tid, enabled=val not in (b"0", "0")))


# ─────────────────────────────────────────────────────────────────────────────
# Feedback / false-positive
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/rules/{rule_id}/feedback", response_model=APIResponse[FeedbackResponse])
async def rule_feedback(
    rule_id:   uuid.UUID,
    payload:   FeedbackRequest,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[FeedbackResponse]:
    repo = AutoResponseRuleRepository(db)
    rule = await repo.get(rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule = await repo.record_false_positive(rule, payload.suppress_min)
    logger.warning("are_false_positive_reported",
                   rule_id=str(rule_id), suppress_min=payload.suppress_min, reason=payload.reason)
    return APIResponse(data=FeedbackResponse(
        rule_id=str(rule_id),
        false_positive_count=rule.false_positive_count,
        suppressed_until=rule.suppressed_until,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Manual approval
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/pending/{approval_key}/approve", response_model=APIResponse[dict])
async def approve_pending(
    approval_key: str,
    payload:      ApprovalRequest,
    request:      Request,
    tenant_id:    Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[dict]:
    """Approve or reject a manual-mode pending action."""
    r   = _redis(request)
    tid = str(tenant_id)
    key = f"acp:{tid}:are:pending:{approval_key}"
    raw = await r.get(key)
    if not raw:
        raise HTTPException(status_code=404, detail="Pending approval not found or expired")

    import json
    pending = json.loads(raw if isinstance(raw, str) else raw.decode())
    await r.delete(key)

    if payload.approved:
        # Re-queue the incident so the ARE worker processes it in auto mode
        incident = pending["incident"]
        incident["_manual_approved"] = True
        await r.xadd("acp:incidents:queue", {"data": json.dumps(incident)}, maxlen=50_000, approximate=True)
        return APIResponse(data={"status": "approved", "re_queued": True})

    return APIResponse(data={"status": "rejected", "note": payload.note})


@router.get("/pending", response_model=APIResponse[list[dict]])
async def list_pending(
    request:   Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[list[dict]]:
    """List all pending manual-approval actions for this tenant."""
    import json as _json
    r      = _redis(request)
    tid    = str(tenant_id)
    prefix = f"acp:{tid}:are:pending:"
    keys   = await r.keys(f"{prefix}*")
    items  = []
    for k in keys[:50]:
        raw = await r.get(k)
        if raw:
            try:
                data = _json.loads(raw if isinstance(raw, str) else raw.decode())
                # Backfill approval_key from the Redis key name for older records
                if "approval_key" not in data:
                    key_str = k.decode() if isinstance(k, bytes) else k
                    data["approval_key"] = key_str[len(prefix):]
                items.append(data)
            except Exception:
                pass
    return APIResponse(data=items)


# ─────────────────────────────────────────────────────────────────────────────
# Prometheus-style metrics
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/metrics", response_model=APIResponse[dict])
async def are_metrics(
    request:   Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[dict]:
    """Return ARE counter metrics from Redis."""
    r   = _redis(request)
    tid = str(tenant_id)

    async def _get(key: str) -> int:
        val = await r.get(f"acp:{tid}:are:metrics:{key}")
        return int(val or 0)

    # Fetch all metric keys for this tenant
    pattern = f"acp:{tid}:are:metrics:*"
    keys    = await r.keys(pattern)

    metrics: dict[str, int] = {}
    for k in keys:
        name = k.decode() if isinstance(k, bytes) else k
        short = name.replace(f"acp:{tid}:are:metrics:", "")
        val   = await r.get(k)
        metrics[short] = int(val or 0)

    # Also expose global per-tenant kill-switch toggle
    enabled_val = await r.get(f"acp:{tid}:are:enabled")
    metrics["are_enabled"] = 0 if enabled_val in (b"0", "0") else 1

    return APIResponse(data={
        "tenant_id": tid,
        "metrics":   metrics,
        # Convenience roll-ups
        "triggers_total":    sum(v for k, v in metrics.items() if k.startswith("triggers_total")),
        "suggestions_total": sum(v for k, v in metrics.items() if k.startswith("suggestions_total")),
        "suppressed_total":  sum(v for k, v in metrics.items() if k.startswith("suppressed_total")),
        "manual_pending":    sum(v for k, v in metrics.items() if k.startswith("manual_pending")),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Simulation (dry-run, unchanged API — richer output)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/simulate", response_model=APIResponse[ARESimulateResponse])
async def simulate(
    payload:   ARESimulateRequest,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[ARESimulateResponse]:
    from datetime import timedelta
    from sqlalchemy import select as sa_select

    repo = AutoResponseRuleRepository(db)
    rule = await repo.get(payload.rule_id, tenant_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    hours = _TIME_RANGE_HOURS.get(payload.time_range, 24)
    since = __import__("datetime").datetime.now(__import__("datetime").timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        sa_select(Incident)
        .where(Incident.tenant_id == tenant_id, Incident.created_at >= since)
        .order_by(Incident.created_at.desc())
        .limit(500)
    )
    incidents = list(result.scalars().all())

    matches: list[ARESimulateMatchItem] = []
    agents_hit: set[str] = set()
    matched_count = 0

    for inc in incidents:
        d = {"severity": inc.severity, "risk_score": inc.risk_score,
             "tool": inc.tool, "agent_id": inc.agent_id, "violation_count": inc.violation_count}
        if _check_condition(rule.conditions, d, inc.violation_count):
            matched_count += 1
            agents_hit.add(inc.agent_id)
            if len(matches) < 10:
                matches.append(ARESimulateMatchItem(
                    incident_id=str(inc.id), agent_id=inc.agent_id,
                    severity=inc.severity, risk_score=inc.risk_score,
                    tool=inc.tool, created_at=inc.created_at.isoformat(),
                ))

    total = len(incidents)
    return APIResponse(data=ARESimulateResponse(
        rule_id=str(rule.id),
        total_events=total,
        would_trigger=matched_count,
        mitigated_pct=round((matched_count / total * 100) if total else 0, 1),
        actions_preview=rule.actions,
        affected_agents=list(agents_hit)[:20],
        sample_matches=matches,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Replay engine (re-run historical events through current rules)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/replay", response_model=APIResponse[dict])
async def replay(
    payload:   dict,
    db:        Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[dict]:
    """
    Dry-run current ARE rules against historical audit log entries.

    Body (all optional):
      rule_ids:  list[str]  — specific rule UUIDs to replay (default: all active)
      hours:     int        — lookback window (default 24, max 168)
      limit:     int        — max events to process (default 500)
    """
    from services.api.are_replay import replay_rules

    rule_id_strs: list[str] = payload.get("rule_ids") or []
    hours:  int = min(int(payload.get("hours", 24)), 168)
    limit:  int = min(int(payload.get("limit", 500)), 2000)

    rule_ids: list[uuid.UUID] | None = None
    if rule_id_strs:
        try:
            rule_ids = [uuid.UUID(r) for r in rule_id_strs]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid rule_id: {exc}") from exc

    result = await replay_rules(db, tenant_id, rule_ids=rule_ids, hours=hours, limit=limit)
    return APIResponse(data=result)


# ─────────────────────────────────────────────────────────────────────────────
# P99 latency per rule
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/latency", response_model=APIResponse[dict])
async def are_latency(
    request:   Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    db:        Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict]:
    """
    Return p50/p95/p99 latency statistics per rule from the rolling Redis sorted set.
    """
    r   = _redis(request)
    tid = str(tenant_id)

    # Discover all per-rule latency keys
    pattern = f"acp:{tid}:are:latency:*"
    keys    = await r.keys(pattern)

    result: dict[str, dict] = {}
    for k in keys:
        key_str  = k.decode() if isinstance(k, bytes) else k
        rule_id  = key_str.replace(f"acp:{tid}:are:latency:", "")
        # Scores are latency_ms values; members sorted by score ascending
        samples  = await r.zrange(key_str, 0, -1, withscores=True)
        if not samples:
            continue
        vals = sorted(float(score) for _, score in samples)
        n    = len(vals)

        def _pct(p: float) -> float:
            idx = int(n * p / 100)
            return round(vals[min(idx, n - 1)], 2)

        result[rule_id] = {
            "count": n,
            "p50":   _pct(50),
            "p95":   _pct(95),
            "p99":   _pct(99),
            "min":   round(vals[0], 2),
            "max":   round(vals[-1], 2),
        }

    return APIResponse(data={"tenant_id": tid, "latency_by_rule": result})
