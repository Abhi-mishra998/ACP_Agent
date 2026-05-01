from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import Depends, FastAPI

from sdk.common.audit_stream import push_audit_event
from sdk.common.config import settings
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.decision.engine import decision_engine
from services.decision.router import router as decision_router
from services.decision.schemas import Decision, DecisionContext, OrchestrationRequest
from services.decision.intelligence import GroqSecurityBrain

logger = structlog.get_logger(__name__)

redis = get_redis_client(settings.REDIS_URL, decode_responses=False)

# Initialized in lifespan so the AsyncGroq SDK client is properly closed on shutdown
groq_brain: GroqSecurityBrain | None = None

# Module-level persistent HTTP client — avoids creating a new connection pool per request
_http_client: httpx.AsyncClient | None = None
_NIL_UUID = uuid.UUID(int=0)

# Per-call timeout budget so the decision service always responds well within the
# gateway's 2s asyncio.wait_for deadline:
#   registry  0.4s  (skipped for admin nil-UUID fast-path)
#   usage     0.4s
#   gather    1.0s  (policy + behavior in parallel, each bounded by client read=0.8s)
#   headroom  ~0.2s
_T_FAST = httpx.Timeout(connect=0.3, read=0.4, write=0.3, pool=0.3)
_T_GATHER = httpx.Timeout(connect=0.3, read=0.8, write=0.3, pool=0.3)
_T_GATHER_TOTAL = 1.0  # asyncio.wait_for cap on the parallel fan-out


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    global _http_client, groq_brain
    _http_client = httpx.AsyncClient(timeout=_T_GATHER)
    try:
        groq_brain = GroqSecurityBrain(settings.GROQ_API_KEY)
        logger.info("groq_brain_initialized", model_fast=settings.GROQ_MODEL_FAST, model_deep=settings.GROQ_MODEL)
    except Exception as exc:
        logger.warning("groq_brain_init_failed", error=str(exc))
        groq_brain = None
    yield
    if groq_brain:
        await groq_brain.close()
    if _http_client:
        await _http_client.aclose()
    await redis.aclose()


app = FastAPI(
    title="ACP Decision Service",
    description="Global decision engine for Agent Control Plane",
    version="1.0.0",
    lifespan=lifespan,
)

setup_app(app, "decision")

from sdk.common.auth import verify_internal_secret


@app.post("/evaluate", response_model=Decision)
async def evaluate_decision(
    req: OrchestrationRequest,
    _: str = Depends(verify_internal_secret),
    x_agent_claims: str | None = None,
) -> Decision:
    """
    Orchestrates context evaluation:
    1. Agent status resolved from X-Agent-Claims header (zero Registry calls)
       or falls back to Registry HTTP if header absent (old tokens / admin path).
    2. Records Usage & Checks Budget (CostEngine)
    3. Fan-out: Policy + Behavior in parallel
    4. Computes final Decision via DecisionEngine
    """
    import json as _json

    headers = {
        "X-Internal-Secret": settings.INTERNAL_SECRET,
        "X-Tenant-ID": str(req.tenant_id)
    }

    client: httpx.AsyncClient = _http_client or httpx.AsyncClient(timeout=3.0)

    # 1. Resolve agent data — prefer JWT claims over Registry HTTP
    agent_meta: dict = {}

    # Gateway injects X-Agent-Claims with JWT permissions when available
    raw_claims = req.metadata.get("agent_claims") if req.metadata else None
    if raw_claims:
        try:
            agent_meta = _json.loads(raw_claims) if isinstance(raw_claims, str) else raw_claims
        except Exception:
            pass

    if not agent_meta and req.agent_id != _NIL_UUID:
        registry_url = f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{req.agent_id}"
        try:
            agent_res = await client.get(registry_url, headers=headers, timeout=_T_FAST)
            if agent_res.status_code == 200:
                reg_json = agent_res.json()
                agent_meta = reg_json.get("data", reg_json) if reg_json.get("success") else reg_json
        except Exception as exc:
            logger.warning("registry_unreachable_in_decision", error=str(exc))

    agent_status = agent_meta.get("status", agent_meta.get("agent_status", "active"))
    if agent_status in ("quarantined", "terminated"):
        return Decision(action="deny", risk=1.0, reasons=[f"Agent is {agent_status.upper()}"])

    # Defense-in-depth permission check (uses embedded claims when available)
    allowed_tools = [
        p["tool_name"]
        for p in agent_meta.get("permissions", [])
        if str(p.get("action", "")).upper() == "ALLOW"
    ]
    if allowed_tools and req.tool not in allowed_tools and "*" not in allowed_tools:
        return Decision(action="deny", risk=1.0, reasons=[f"Tool '{req.tool}' not in agent permissions"])

    # 2. Fan-out: Usage + Policy (OPA) + Behavior in parallel
    opa_payload = {
        "tenant_id": str(req.tenant_id),
        "agent_id": str(req.agent_id),
        "tool": req.tool,
        "risk_score": req.inference_risk,
        "behavior_history": [],
        "request_id": req.request_id,
        "metadata": {"client_ip": req.client_ip},
    }

    async def _call_usage():
        if not (req.tokens and req.tokens > 0):
            return None
        try:
            return await client.post(
                f"{settings.USAGE_SERVICE_URL.rstrip('/')}/usage/record",
                timeout=_T_FAST,
                json={
                    "tenant_id": str(req.tenant_id),
                    "agent_id": str(req.agent_id),
                    "tool": req.tool,
                    "units": req.tokens,
                    "cost": 0.0,
                },
                headers=headers,
            )
        except Exception as exc:
            logger.warning("usage_service_unavailable", error=str(exc), agent_id=str(req.agent_id))
            return None

    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                _call_usage(),
                client.post(f"{settings.POLICY_SERVICE_URL.rstrip('/')}/policy/evaluate", json=opa_payload, headers=headers),
                client.post(f"{settings.BEHAVIOR_SERVICE_URL.rstrip('/')}/analyze", json={
                    "tenant_id": str(req.tenant_id), "agent_id": str(req.agent_id),
                    "tool": req.tool, "tokens": req.tokens,
                }, headers=headers),
                return_exceptions=True,
            ),
            timeout=_T_GATHER_TOTAL,
        )
    except asyncio.TimeoutError:
        logger.warning("decision_fanout_timeout", agent_id=str(req.agent_id))
        results = [None, None, None]

    usage_res, policy_res, behavior_res = results[0], results[1], results[2]

    cost_risk = 0.0
    if isinstance(usage_res, httpx.Response) and usage_res.status_code in (200, 201):
        cost_data = usage_res.json().get("data", {})
        cost_risk = float(cost_data.get("risk", 0.0))
    elif isinstance(usage_res, Exception):
        logger.warning("usage_service_unavailable", error=str(usage_res), agent_id=str(req.agent_id))

    policy_data: dict = {"allowed": False, "reason": "policy_timeout", "risk_adjustment": 0.0}
    if isinstance(policy_res, httpx.Response) and policy_res.status_code == 200:
        policy_data.update(policy_res.json().get("data", {}))
    elif isinstance(policy_res, httpx.Response) and policy_res.status_code == 403:
        policy_data.update({"allowed": False, "reason": policy_res.json().get("detail", "Access Denied")})

    behavior_data: dict = {"behavior_risk": 0.0, "anomaly_score": 0.0, "cross_agent_risk": 0.0, "confidence": 1.0, "flags": []}
    if isinstance(behavior_res, httpx.Response) and behavior_res.status_code == 200:
        behavior_data.update(behavior_res.json().get("data", {}))

    # 4. Assemble DecisionContext and evaluate
    ctx = DecisionContext(
        tenant_id=req.tenant_id,
        agent_id=req.agent_id,
        tool=req.tool,
        request_id=req.request_id,
        policy_allowed=bool(policy_data.get("allowed", False)),
        policy_reason=policy_data.get("reason"),
        policy_risk_adjustment=float(policy_data.get("risk_adjustment", 0.0)),
        inference_risk=float(req.inference_risk),
        inference_flags=list(req.inference_flags),
        behavior_risk=float(behavior_data.get("behavior_risk", 0.0)),
        anomaly_score=float(behavior_data.get("anomaly_score", 0.0)),
        cost_risk=float(cost_risk),
        cross_agent_risk=float(behavior_data.get("cross_agent_risk", 0.0)),
        confidence=float(behavior_data.get("confidence", 1.0)),
        behavior_flags=list(behavior_data.get("flags", [])),
    )

    decision = decision_engine.evaluate(ctx)

    # AI-Powered Security Brain (Groq LLM enrichment — optional override)
    if groq_brain and (decision.risk >= 0.30 or decision.action.value != "allow"):
        try:
            ai_decision = await asyncio.wait_for(groq_brain.evaluate(ctx, decision), timeout=0.5)
            if ai_decision:
                decision = ai_decision
        except (asyncio.TimeoutError, Exception) as exc:
            logger.warning("groq_brain_eval_failed", error=str(exc))

    # Async audit logging (non-blocking, best-effort)
    asyncio.create_task(push_audit_event(
        redis=redis,
        tenant_id=req.tenant_id,
        agent_id=req.agent_id,
        action="decision_evaluate",
        tool=req.tool,
        decision=decision.action.value,
        reason="; ".join(str(r) for r in decision.reasons) if decision.reasons else None,
        metadata={
            "risk_score": decision.risk,
            "signals": getattr(decision, "signals", {}),
            "request_id": req.request_id,
        },
        request_id=req.request_id,
    ))

    # Push high-risk events to Groq analytics queue (async, best-effort)
    if decision.action.value in ("block", "kill", "escalate", "deny"):
        try:
            await redis.xadd(
                "acp:groq_queue",
                {
                    "event_id": str(uuid.uuid4()),
                    "agent_id": str(req.agent_id),
                    "tenant_id": str(req.tenant_id),
                    "risk_score": str(decision.risk),
                    "decision": decision.action.value,
                    "tool": req.tool,
                    "payload_hash": req.payload_hash,
                },
                maxlen=10_000,
            )
        except Exception:
            pass

    return decision

app.include_router(decision_router)
