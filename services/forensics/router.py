import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.db import get_db, get_tenant_id
from services.audit.models import AuditLog
from services.decision.engine import decision_engine
from services.decision.schemas import DecisionContext

router = APIRouter(prefix="/forensics", tags=["Forensics"], dependencies=[Depends(verify_internal_secret)])

@router.get("/investigation", tags=["Forensics"])
async def list_investigations(
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    db: AsyncSession = Depends(get_db),
    limit: int = 20
) -> dict[str, Any]:
    """Return list of recent high-risk investigations scoped to the authenticated tenant."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.decision == "deny", AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()
    return {
        "success": True,
        "data": [
            {
                "id": str(log.id),
                "agent_id": str(log.agent_id),
                "timestamp": log.timestamp.isoformat(),
                "tool": log.tool,
                "risk_score": log.metadata_json.get("risk_score", 0.0),
                "reason": log.metadata_json.get("reason", "Malicious intent")
            }
            for log in logs
        ]
    }

@router.get("/replay/{agent_id}")
async def replay_agent_behavior(
    agent_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    limit: int = 50,
    db: AsyncSession = Depends(get_db)  # noqa: B008
) -> dict[str, Any]:
    """
    Forensic Replay System.
    Re-evaluates historical agent actions against the current risk model
    to identify 'Near Misses' or model drifts.
    """
    # 1. Pull historical audit logs — scoped to tenant to prevent cross-tenant leakage
    stmt = (
        select(AuditLog)
        .where(AuditLog.agent_id == agent_id, AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    if not logs:
        raise HTTPException(status_code=404, detail="No audit logs found for this agent.")

    replays = []

    # 2. Replay each decision
    for entry in logs:
        # Reconstruct DecisionContext from audit metadata (P1-6 FIX)
        # In a real system, we'd store the full raw input or signal vector
        meta = entry.metadata_json or {}

        req = DecisionContext(
            tenant_id=entry.tenant_id,
            agent_id=entry.agent_id,
            tool=entry.tool or "unknown",
            policy_allowed=(entry.decision != "deny"),
            inference_risk=meta.get("inference_risk", 0.0),
            behavior_risk=meta.get("behavior_risk", 0.0),
            anomaly_score=meta.get("anomaly_score", 0.0),
            cross_agent_risk=meta.get("cross_agent_risk", 0.0),
            usage_metrics=meta.get("usage_metrics", {})
        )

        # 3. New Evaluation
        new_decision = decision_engine.evaluate(req)

        replays.append({
            "event_id": str(entry.id),
            "timestamp": entry.timestamp,
            "tool": entry.tool,
            "old_decision": entry.decision.upper(),
            "new_decision": new_decision.action.upper(),
            "old_risk": meta.get("risk_score", 0.0),
            "new_risk": new_decision.risk,
            "drift": round(abs(new_decision.risk - (meta.get("risk_score") or 0.0)), 3),
            "reasons": new_decision.reasons
        })

    return {
        "agent_id": str(agent_id),
        "replay_count": len(replays),
        "results": replays
    }


@router.get("/investigation/{agent_id}")
async def get_investigation_report(
    agent_id: uuid.UUID,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict[str, Any]:
    """
    UI-3 FIX: Build a full investigation profile for an agent
    combining audit history, risk profile, and behavioural signals.
    """
    from sqlalchemy import func

    # Total events scoped to tenant to prevent cross-tenant leakage
    total_stmt = select(func.count(AuditLog.id)).where(
        AuditLog.agent_id == agent_id, AuditLog.tenant_id == tenant_id
    )
    total_res = await db.execute(total_stmt)
    total_events = total_res.scalar_one_or_none() or 0

    # Last 20 events
    recent_stmt = (
        select(AuditLog)
        .where(AuditLog.agent_id == agent_id, AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(20)
    )
    recent_res = await db.execute(recent_stmt)
    recent_logs = recent_res.scalars().all()

    if not recent_logs:
        raise HTTPException(status_code=404, detail="No data found for this agent.")

    decisions = {}
    for log in recent_logs:
        decisions[log.decision] = decisions.get(log.decision, 0) + 1

    avg_risk = (
        sum(log.metadata_json.get("risk_score", 0.0) for log in recent_logs)
        / len(recent_logs)
    )

    return {
        "agent_id": str(agent_id),
        "total_events": total_events,
        "avg_risk_score": round(avg_risk, 4),
        "decision_breakdown": decisions,
        "recent_events": [
            {
                "id": str(log.id),
                "timestamp": log.timestamp.isoformat(),
                "tool": log.tool,
                "decision": log.decision,
                "risk_score": log.metadata_json.get("risk_score", 0.0),
                "reasons": log.metadata_json.get("reasons", []),
            }
            for log in recent_logs
        ],
    }
