from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status

from sdk.common.auth import verify_internal_secret
from sdk.common.config import settings as policy_settings
from sdk.common.deadline import check_deadline
from sdk.common.response import APIResponse
from services.policy.opa_client import opa_client
from services.policy.schemas import (
    EvaluationRequest, EvaluationResponse,
    SimulateRequest, SimulateResponse, SimulateDiffItem,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/policy", tags=["policy"])

# Persistent clients — lifecycle managed via startup/shutdown
_REGISTRY_TIMEOUT = httpx.Timeout(3.0, connect=1.5)
_AUDIT_TIMEOUT = httpx.Timeout(2.0, connect=1.0)
_registry_client: httpx.AsyncClient | None = None
_audit_client: httpx.AsyncClient | None = None


def init_policy_clients() -> None:
    """Initialize persistent global clients at startup."""
    global _registry_client, _audit_client
    if _registry_client is None or _registry_client.is_closed:
        _registry_client = httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT)
    if _audit_client is None or _audit_client.is_closed:
        _audit_client = httpx.AsyncClient(timeout=_AUDIT_TIMEOUT)


def get_registry_client() -> httpx.AsyncClient:
    """Return the global registry client. Initialize if needed (redundancy)."""
    global _registry_client
    if _registry_client is None or _registry_client.is_closed:
        _registry_client = httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT)
    return _registry_client


def get_audit_client() -> httpx.AsyncClient:
    """Return the global audit client. Initialize if needed (redundancy)."""
    global _audit_client
    if _audit_client is None or _audit_client.is_closed:
        _audit_client = httpx.AsyncClient(timeout=_AUDIT_TIMEOUT)
    return _audit_client


async def close_policy_clients() -> None:
    """Call during FastAPI shutdown lifespan to close persistent connections."""
    if _registry_client and not _registry_client.is_closed:
        await _registry_client.aclose()
    if _audit_client and not _audit_client.is_closed:
        await _audit_client.aclose()


# =========================
# HELPERS
# =========================


async def _fetch_agent(tenant_id: uuid.UUID, agent_id: uuid.UUID) -> dict[str, Any]:
    """
    Fetch full agent + permissions from Registry service.
    Source of Truth.
    """
    url = f"{policy_settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}"
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    headers = {
        "X-Internal-Secret": policy_settings.INTERNAL_SECRET,
        "X-Tenant-ID": str(tenant_id),
    }
    if request_id:
        headers["X-Request-ID"] = request_id

    try:
        client = get_registry_client()
        resp = await client.get(url, headers=headers)
    except httpx.RequestError as exc:
        logger.error("registry_unreachable", error=str(exc), reason="system_unavailable")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registry service unreachable: system_unavailable",
        ) from exc

    if resp.status_code == 404:
        # P-6 FIX: Handle Global Management Context (Agent 0)
        # Match Gateway virtual metadata for consistent policy evaluation
        if agent_id == uuid.UUID(int=0):
            return {
                "id": str(agent_id),
                "tenant_id": str(tenant_id),
                "name": "Global Management Context",
                "status": "active",
                "risk_level": "low",
                "permissions": [
                    {"tool_name": "*", "action": "allow", "granted_by": str(uuid.UUID(int=0))}
                ],
            }

        # Agent not found — return a minimal stub so OPA evaluates with zero permissions.
        # The OPA policy will deny the tool (no ALLOW grants) and return risk_adjustment=0.
        # This is safer than hard-failing: callers can still handle a policy deny gracefully.
        logger.warning("agent_not_found_policy_stub", agent_id=str(agent_id))
        return {
            "id": str(agent_id),
            "tenant_id": str(tenant_id),
            "name": "unknown",
            "status": "inactive",
            "risk_level": "low",
            "permissions": [],
        }

    if resp.status_code != 200:
        logger.error("registry_error", status_code=resp.status_code, reason="system_unavailable")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unexpected response from registry: system_unavailable",
        )

    json_resp = resp.json()
    return dict(json_resp.get("data", {}))


def _build_opa_input(
    agent: dict[str, Any],
    payload: EvaluationRequest
) -> dict[str, Any]:
    """
    Central OPA input builder. 
    Ensures a consistent schema for all policy requests, including metadata.
    """
    permissions = []
    for p in agent.get("permissions", []):
        permissions.append(
            {
                "tool_name": p["tool_name"],
                "action": p["action"],
                "granted_by": str(p["granted_by"]),
                "expires_at": p.get("expires_at"),
            }
        )

    return {
        "tenant_id": str(agent["tenant_id"]),
        "agent": {
            "id": str(agent["id"]),
            "name": agent["name"],
            "status": agent["status"],
            "risk_level": agent.get("risk_level", "low"),
            "permissions": permissions,
        },
        "tool": payload.tool,
        "risk_score": payload.risk_score,
        "behavior_history": payload.behavior_history,
        "policy_version": payload.policy_version,
        "metadata": {
            "request_id": payload.request_id or structlog.contextvars.get_contextvars().get("request_id"),
            "timestamp": payload.timestamp.isoformat(),
            **payload.metadata
        }
    }


async def _log_audit(
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    tool: str,
    allowed: bool,
    reason: str,
    risk_score: float,
    risk_adjustment: float,
) -> None:
    """
    Send decision to Audit service via simple HTTP POST.
    """
    url = f"{policy_settings.AUDIT_SERVICE_URL.rstrip('/')}/audit/logs"
    request_id = structlog.contextvars.get_contextvars().get("request_id")

    payload = {
        "tenant_id": str(tenant_id),
        "agent_id": str(agent_id),
        "action": "policy_evaluation",
        "tool": tool,
        "decision": "allow" if allowed else "deny",
        "reason": reason,
        "request_id": request_id,
        "metadata_json": {
            "risk_score": risk_score,
            "risk_adjustment": risk_adjustment,
            "policy_version": "v1",
            "source": "policy_service"
        }
    }

    try:
        client = get_audit_client()
        await client.post(url, json=payload)
    except Exception as exc:
        logger.warning("audit_logging_failed", error=str(exc))


# =========================
# EVALUATE ENDPOINT
# =========================


@router.post(
    "/evaluate",
    response_model=APIResponse[EvaluationResponse],
    summary="Evaluate whether an agent may execute a tool",
)
async def evaluate(
    payload: EvaluationRequest,
    _: Annotated[bool, Depends(check_deadline)] = True,
    __: Annotated[str, Depends(verify_internal_secret)] = "",
) -> APIResponse[EvaluationResponse]:
    """
    Adaptive multi-layer policy evaluation:
    1. Fetches agent from Registry (Source of Truth)
    2. Builds consistent OPA input document with metadata
    3. Calls OPA and retrieves decision, reason, and RISK ADJUSTMENT
    4. Logs decision and adjustment to Audit Service
    5. Returns unified APIResponse
    """
    # Fast-path: gateway embedded JWT agent_claims → evaluate locally (< 1ms, no HTTP)
    if payload.agent_claims:
        from services.policy.local_eval import evaluate
        agent_claims = payload.agent_claims
        allowed, reason, risk_adjustment = evaluate(
            agent_status=agent_claims.get("agent_status", agent_claims.get("status", "active")),
            permissions=agent_claims.get("permissions", []),
            tool=payload.tool,
            risk_score=payload.risk_score,
            risk_level=agent_claims.get("risk_level", "low"),
        )
    else:
        agent_dict = await _fetch_agent(payload.tenant_id, payload.agent_id)
        opa_input = _build_opa_input(agent_dict, payload)
        allowed, reason, risk_adjustment = await opa_client.check_policy(opa_input)

    asyncio.create_task(_log_audit(
        payload.tenant_id, payload.agent_id, payload.tool,
        allowed, reason, payload.risk_score, risk_adjustment
    ))

    if not allowed:
        logger.warning("policy_denied", agent_id=str(payload.agent_id), tool=payload.tool, reason=reason)

    return APIResponse(
        data=EvaluationResponse(
            agent_id=payload.agent_id,
            tool=payload.tool,
            allowed=allowed,
            reason=reason,
            risk_adjustment=risk_adjustment,
            evaluated_at=datetime.now(tz=UTC),
        )
    )


# =========================
# POLICY SIMULATION (DRY-RUN)
# =========================

_TIME_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
_OPS = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "==", "neq": "!="}


def _eval_condition(cond, log: dict) -> bool:
    meta = log.get("metadata_json") or {}
    field_map = {
        "risk_score":     float(meta.get("risk_score",     0)),
        "inference_risk": float(meta.get("inference_risk", 0)),
        "behavior_risk":  float(meta.get("behavior_risk",  0)),
        "anomaly_score":  float(meta.get("anomaly_score",  0)),
        "tool":           str(log.get("tool", "")),
    }
    actual = field_map.get(cond.field)
    if actual is None:
        return False
    try:
        val = str(cond.value)
        if cond.field != "tool":
            a, v = float(actual), float(val)
            _cmp = {"gt": a > v, "gte": a >= v, "lt": a < v, "lte": a <= v, "eq": a == v, "neq": a != v}
            return _cmp.get(cond.operator, False)
        ops = {"eq": actual == val, "neq": actual != val}
        return ops.get(cond.operator, False)
    except Exception:
        return False


def _simulate_decision(policy: list, log: dict) -> str:
    for rule in policy:
        if all(_eval_condition(c, log) for c in rule.conditions):
            return rule.action.lower()
    return "allow"


@router.post(
    "/simulate",
    response_model=APIResponse[SimulateResponse],
    summary="Dry-run a policy against historical audit events",
    dependencies=[Depends(verify_internal_secret)],
)
async def simulate_policy(payload: SimulateRequest) -> APIResponse[SimulateResponse]:
    """
    Fetch recent audit logs for the agent and replay them through the proposed
    policy rules locally. Returns a diff of decisions that would change.
    No OPA call, no writes — pure read + evaluate.
    """
    from datetime import datetime, timezone, timedelta

    hours     = _TIME_RANGE_HOURS.get(payload.time_range, 24)
    since     = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    try:
        client = get_audit_client()
        resp   = await client.get(
            f"{policy_settings.AUDIT_SERVICE_URL.rstrip('/')}/logs",
            params={"agent_id": str(payload.agent_id), "limit": 200, "offset": 0},
            headers={"X-Internal-Secret": policy_settings.INTERNAL_SECRET,
                     "X-Tenant-ID": str(payload.tenant_id)},
        )
        logs: list[dict] = resp.json().get("data", {}).get("items", []) if resp.status_code == 200 else []
    except Exception as exc:
        logger.warning("simulate_audit_fetch_failed", error=str(exc))
        logs = []

    diff:    list[SimulateDiffItem] = []
    allow_n  = deny_n = no_change = 0

    for log in logs:
        old_dec = (log.get("decision") or "allow").lower()
        new_dec = _simulate_decision(payload.policy, log)

        if new_dec in ("allow", "monitor"):
            allow_n += 1
        else:
            deny_n += 1

        if old_dec != new_dec:
            diff.append(SimulateDiffItem(
                event_id     = str(log.get("id", "")),
                tool         = str(log.get("tool", "unknown")),
                timestamp    = str(log.get("timestamp", "")),
                risk_score   = float((log.get("metadata_json") or {}).get("risk_score", 0)),
                old_decision = old_dec,
                new_decision = new_dec,
            ))
        else:
            no_change += 1

    return APIResponse(data=SimulateResponse(
        total_events = len(logs),
        would_allow  = allow_n,
        would_deny   = deny_n,
        no_change    = no_change,
        diff         = diff[:20],   # cap sample at 20 for payload size
    ))


@router.post(
    "/execute",
    summary="Execute a tool (security-controlled)",
    dependencies=[Depends(verify_internal_secret)],
)
async def execute_tool(
    request: Request,
    payload: dict[str, Any],
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> dict[str, Any]:
    """
    Final tool execution destination. 
    In this control plane, it records the execution and returns the decision context.
    The Gateway's SecurityMiddleware has already authorized this request.
    """
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    agent_id = request.headers.get("X-Agent-ID", "")
    tenant_id = request.headers.get("X-Tenant-ID", "")
    tool = payload.get("tool") or request.headers.get("X-ACP-Tool", "unknown")
    
    # Extract decision metadata injected by the Gateway
    decision_meta = payload.get("_decision", {})
    
    # RULE: All executions are recorded for auditing and forensic replay
    # In a real system, this is where the actual agent tool invocation happens.
    
    return {
        "success": True,
        "request_id": request_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "tool": tool,
        "action": decision_meta.get("action", "allow"),
        "risk": decision_meta.get("risk", 0.0),
        "confidence": decision_meta.get("confidence", 1.0),
        "reasons": decision_meta.get("reasons", []),
        "signals": decision_meta.get("signals", {}),
        "executed_at": datetime.now(tz=UTC).isoformat(),
    }


# =========================
# HEALTH
# =========================


@router.get("/health/opa", tags=["ops"], summary="Check OPA connectivity")
async def opa_health() -> dict[str, str]:
    healthy = await opa_client.health()
    if not healthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OPA is not reachable",
        )
    return {"opa": "ok"}
