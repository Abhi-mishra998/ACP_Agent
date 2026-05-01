"""
ACP Gateway Service — Pure Reverse Proxy
==========================================
All fixes applied:
  P0-1  proxy_auth_token now has `request: Request` parameter
  P0-5  Removed embedded routers (audit, registry, api_key) — pure httpx proxy only
  P1-3  Cookies use secure=True only in production (ENVIRONMENT setting)
  P2-7  Audit proxy URLs fixed: /logs/summary not /audit/logs/summary
  Added: /decision/kill-switch, /decision/history, /forensics/replay proxy routes
  Added: full CRUD agent proxy, api-keys proxy, audit CRUD proxy
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
import structlog
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from sdk.common.config import settings
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.gateway.auth import token_validator
from services.gateway.client import service_client
from services.gateway.middleware import SecurityMiddleware


redis = get_redis_client(settings.REDIS_URL, decode_responses=False)
logger = structlog.get_logger(__name__)


class PubSubManager:
    """
    Shared Redis Pub/Sub fan-out for SSE endpoints.

    ONE Redis subscription per (worker, channel) regardless of how many SSE
    clients are connected. Per-client messages land in bounded asyncio.Queue
    instances (maxsize=100); when a queue is full the oldest message is dropped
    so slow consumers can't stall the fan-out.
    """

    def __init__(self, r: Any) -> None:
        self._redis = r
        self._lock = asyncio.Lock()
        # channel → (pubsub, set[Queue], background_task)
        self._subs: dict[str, tuple[Any, set[asyncio.Queue], asyncio.Task]] = {}

    async def subscribe(self, channel: str) -> asyncio.Queue:
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue(maxsize=100)
            if channel in self._subs:
                _, queues, _ = self._subs[channel]
                queues.add(q)
            else:
                pubsub = self._redis.pubsub()
                await pubsub.subscribe(channel)
                queues: set[asyncio.Queue] = {q}
                task = asyncio.create_task(self._reader(channel, pubsub, queues))
                self._subs[channel] = (pubsub, queues, task)
            return q

    async def unsubscribe(self, channel: str, q: asyncio.Queue) -> None:
        async with self._lock:
            if channel not in self._subs:
                return
            pubsub, queues, task = self._subs[channel]
            queues.discard(q)
            if not queues:
                task.cancel()
                try:
                    await pubsub.unsubscribe(channel)
                    await pubsub.aclose()
                except Exception:
                    pass
                del self._subs[channel]

    async def _reader(
        self, channel: str, pubsub: Any, queues: set[asyncio.Queue]
    ) -> None:
        try:
            while True:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if msg and msg.get("type") == "message":
                    data = msg.get("data", b"")
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    for q in list(queues):
                        if q.full():
                            try:
                                q.get_nowait()
                            except asyncio.QueueEmpty:
                                pass
                        try:
                            q.put_nowait(data)
                        except asyncio.QueueFull:
                            pass
                else:
                    await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        async with self._lock:
            for channel, (pubsub, _, task) in list(self._subs.items()):
                task.cancel()
                try:
                    await pubsub.unsubscribe(channel)
                    await pubsub.aclose()
                except Exception:
                    pass
            self._subs.clear()


pubsub_manager = PubSubManager(redis)


def _clamp_int(value: str | None, default: int, lo: int, hi: int) -> int:
    """Parse and clamp a numeric query param to a safe range."""
    try:
        return max(lo, min(hi, int(value))) if value is not None else default
    except (ValueError, TypeError):
        return default


def _internal_headers(request: Request | None = None) -> dict[str, str]:
    """Build internal service-to-service headers, forwarding tenant/auth context.
    X-ACP-Role is injected from the JWT-validated request.state.role — never from
    the client header — to prevent privilege escalation via forged role claims.
    """
    headers: dict[str, str] = {"X-Internal-Secret": settings.INTERNAL_SECRET}
    if request is not None:
        for h in ("X-Tenant-ID", "Authorization", "X-Request-ID", "X-Trace-ID"):
            val = request.headers.get(h)
            if val:
                headers[h] = val
        # Cookie-to-header bridge: promote acp_token cookie → Authorization when
        # no explicit Authorization header was sent (browser/SSE clients use cookies).
        if "Authorization" not in headers:
            cookie_token = request.cookies.get("acp_token")
            if cookie_token:
                headers["Authorization"] = f"Bearer {cookie_token}"
        role = getattr(request.state, "role", None)
        if role:
            headers["X-ACP-Role"] = str(role)
        actor = getattr(request.state, "actor", None)
        if actor:
            headers["X-ACP-Actor"] = str(actor)
    return headers


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    service_client.set_redis(redis)
    _app.state.client = httpx.AsyncClient(timeout=30.0)
    yield
    await pubsub_manager.close()
    await _app.state.client.aclose()
    await redis.aclose()
    await service_client.close()
    from services.policy.router import close_policy_clients
    await close_policy_clients()


app = FastAPI(
    title="ACP Gateway Service",
    description="Secure entry point for all Agent Control Plane operations",
    version="2.0.0",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────


class AuthRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/token", tags=["auth"])
async def proxy_auth_token(request: Request, payload: AuthRequest, response: Response) -> dict[str, Any]:
    """
    P0-1 FIX: Added `request: Request` parameter so request.app.state.client is valid.
    P1-3 FIX: secure= is gated on ENVIRONMENT == 'production'.
    CONTRACT FIX: Returns access_token in BOTH the response body (for API/Locust/SDK
    clients) AND as an httpOnly cookie (for browser clients). This eliminates the
    bearer-vs-cookie split that caused all post-restart auth failures.
    """
    url = f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/login"
    client = request.app.state.client
    try:
        tenant_id = request.headers.get("X-Tenant-ID")
        headers = _internal_headers(request)
        if tenant_id:
            headers["X-Tenant-ID"] = tenant_id
            
        resp = await client.post(
            url, 
            json={"email": payload.email, "password": payload.password},
            headers=headers
        )
        if resp.status_code != 200:
            try:
                err_body = resp.json()
                err_detail = err_body.get("error") or err_body.get("detail") or "Invalid email or password"
                
                # Special handling for validation errors showing missing X-Tenant-ID
                if err_body.get("error") == "Validation failed":
                    for d in err_body.get("meta", {}).get("details", []):
                        if "x-tenant-id" in d.get("loc", []):
                            err_detail = "X-Tenant-ID required"
            except Exception:
                err_detail = "Invalid email or password"
            
            # Allow X-Tenant-ID missing 400s to return status 400
            if resp.status_code == 400 or resp.status_code == 422:
                response.status_code = 400
            else:
                response.status_code = 401
                
            return {
                "success": False,
                "error": err_detail
            }

        data = resp.json() or {}
        info = data.get("data", {})
        token = info.get("access_token")

        if not token:
            return {
                "success": False,
                "error": "Token generation failed"
            }

        is_secure = settings.ENVIRONMENT == "production"

        # Browser clients: httpOnly cookie so JS cannot steal the token
        response.set_cookie(
            key="acp_token",
            value=token,
            httponly=True,
            secure=is_secure,
            samesite="strict",
            max_age=86400,
        )

        # API / Locust / SDK clients: token returned in body so Bearer auth works
        return {
            "success": True,
            "data": {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": info.get("expires_in"),
                "tenant_id": str(info.get("tenant_id", "")),
                "role": info.get("role"),
            },
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/auth/agent/token", tags=["auth"])
async def proxy_agent_token(request: Request) -> Any:
    """Proxy → Identity: issue token for agents. Body: {agent_id, secret} (credentials must be provisioned first via POST /auth/credentials)."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/token",
        json=body,
        headers={**_internal_headers(request), "X-Tenant-ID": request.headers.get("X-Tenant-ID", "")},
    )
    try:
        data = resp.json()
    except Exception:
        data = None
    if resp.status_code != 200 or data is None:
        detail = (data or {}).get("detail", "Agent authentication failed")
        return {"success": False, "error": detail, "data": None}
    return data


@app.post("/auth/logout", tags=["auth"])
async def logout(response: Response) -> dict[str, Any]:
    """Clear session cookies and terminate gateway session."""
    is_secure = settings.ENVIRONMENT == "production"
    response.delete_cookie("acp_token", secure=is_secure, httponly=True, samesite="strict")
    return {"success": True, "message": "Cleared session cookies."}


@app.get("/auth/me", tags=["auth"])
async def get_me(request: Request) -> Any:
    """Proxy → Identity: current user details from JWT."""
    resp = await request.app.state.client.get(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/me",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/introspect", tags=["auth"])
async def introspect_token(request: Request) -> Any:
    """Proxy → Identity: verify token validity and return claims."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/introspect",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/refresh", tags=["auth"])
async def refresh_token(request: Request) -> Any:
    """Proxy → Identity: rotate access token (revokes old, issues new)."""
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/refresh",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/revoke", tags=["auth"])
async def revoke_token(request: Request) -> Any:
    """Proxy → Identity: revoke all tokens for an agent (ADMIN/SECURITY only)."""
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/revoke",
        params=request.query_params,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/users", tags=["auth"])
async def create_user(request: Request) -> Any:
    """Proxy → Identity: create a new user account (first user open; subsequent require ADMIN)."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/users",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/credentials", tags=["auth"])
async def provision_credentials(request: Request) -> Any:
    """Proxy → Identity: provision agent credentials (requires INTERNAL_SECRET via gateway)."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/credentials",
        json=body,
        headers={**_internal_headers(request), "X-Tenant-ID": request.headers.get("X-Tenant-ID", "")},
    )
    return resp.json()


@app.get("/auth/tenants/{tenant_id}", tags=["auth"])
async def get_tenant_metadata(tenant_id: str, request: Request) -> Any:
    """Proxy → Identity: get tier and rate-limit metadata for a tenant (ADMIN only)."""
    resp = await request.app.state.client.get(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/tenants/{tenant_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auth/tenants", tags=["auth"])
async def upsert_tenant(request: Request) -> Any:
    """Proxy → Identity: create or update a tenant's tier and rpm_limit (ADMIN only)."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.IDENTITY_SERVICE_URL.rstrip('/')}/auth/tenants",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


# Add security middleware
app.add_middleware(SecurityMiddleware, redis=redis)

# Consolidated SDK Setup (logging, tracing, metrics, CORS, exception handlers, /health)
setup_app(app, "gateway")

# ─────────────────────────────────────────────────────────────
# P0-5 FIX: Removed include_router(audit_router), include_router(registry_router),
#           include_router(api_key_router).  All routes are now pure httpx proxies
#           so the gateway does NOT need DB connections to downstream databases.
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# REGISTRY PROXY — /agents
# ─────────────────────────────────────────────────────────────

@app.get("/agents", tags=["agents"])
async def list_agents(request: Request) -> Any:
    """Proxy → Registry service list agents."""
    resp = await request.app.state.client.get(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents",
        params=request.query_params,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/agents", tags=["agents"])
async def create_agent(request: Request) -> Any:
    """Proxy → Registry service create agent. Publishes agent_created SSE event."""
    body = await request.json()
    body = dict(body)

    # RULE 3: Tie owner_id to actual user_id from JWT (M-12 Fix)
    actor = getattr(request.state, "actor", "unknown")
    if actor and actor != "unknown":
        body["owner_id"] = actor

    resp = await request.app.state.client.post(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents",
        json=body,
        headers=_internal_headers(request),
    )
    result = resp.json()
    tenant_id_str = request.headers.get("X-Tenant-ID", "")
    if tenant_id_str and resp.status_code in (200, 201):
        try:
            await redis.publish(
                f"acp:events:{tenant_id_str}",
                json.dumps({"type": "agent_created", "data": result.get("data", result)}),
            )
        except Exception as _e:
            logger.debug("sse_publish_failed", event="agent_created", error=str(_e))
    return result


@app.get("/agents/{agent_id}", tags=["agents"])
async def get_agent(agent_id: str, request: Request) -> Any:
    """Proxy → Registry get single agent."""
    resp = await request.app.state.client.get(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.patch("/agents/{agent_id}", tags=["agents"])
async def update_agent(agent_id: str, request: Request) -> Any:
    """Proxy → Registry update agent."""
    body = await request.json()
    resp = await request.app.state.client.patch(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.delete("/agents/{agent_id}", tags=["agents"])
async def delete_agent(agent_id: str, request: Request) -> Any:
    """Proxy → Registry delete agent. Publishes agent_deleted SSE event."""
    resp = await request.app.state.client.delete(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}",
        headers=_internal_headers(request),
    )
    tenant_id_str = request.headers.get("X-Tenant-ID", "")
    if tenant_id_str and resp.status_code in (200, 204):
        try:
            await redis.publish(
                f"acp:events:{tenant_id_str}",
                json.dumps({"type": "agent_deleted", "data": {"agent_id": agent_id}}),
            )
        except Exception as _e:
            logger.debug("sse_publish_failed", event="agent_deleted", error=str(_e))
    return resp.json()


@app.get("/agents/{agent_id}/permissions", tags=["agents"])
async def list_agent_permissions(agent_id: str, request: Request) -> Any:
    """Proxy → Registry list agent permissions."""
    resp = await request.app.state.client.get(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}/permissions",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/agents/{agent_id}/permissions", tags=["agents"])
async def add_agent_permission(agent_id: str, request: Request) -> Any:
    """Proxy → Registry add agent permission.
    Normalises client payloads: maps `allowed` bool → `action`, injects
    `granted_by` from the JWT-authenticated role so callers don't need to send it.
    """
    body = await request.json()
    body = dict(body)  # shallow copy — do not mutate caller's dict

    # Map convenience field `allowed: bool` → `action: ALLOW|DENY`
    if "action" not in body and "allowed" in body:
        body["action"] = "ALLOW" if body.pop("allowed") else "DENY"
    body.pop("allowed", None)  # drop if action was already present

    # Inject granted_by from authenticated role (avoids requiring caller to send it)
    if not body.get("granted_by"):
        role = getattr(request.state, "role", None)
        body["granted_by"] = str(role) if role else "system"

    resp = await request.app.state.client.post(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}/permissions",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.delete("/agents/{agent_id}/permissions/{permission_id}", tags=["agents"])
async def revoke_agent_permission(agent_id: str, permission_id: str, request: Request) -> Any:
    """Proxy → Registry revoke agent permission."""
    resp = await request.app.state.client.delete(
        f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}/permissions/{permission_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# AUDIT PROXY — /audit
# P2-7 FIX: URLs corrected to /logs/... (not /audit/logs/...)
# ─────────────────────────────────────────────────────────────

@app.get("/audit/logs/summary", tags=["audit"])
async def audit_summary(request: Request) -> Any:
    """Proxy → Audit logs summary."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/audit/logs", tags=["audit"])
async def list_audit_logs(request: Request) -> Any:
    """Proxy → Audit logs list."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs",
        params={
            "limit": _clamp_int(request.query_params.get("limit"), 50, 1, 500),
            "offset": _clamp_int(request.query_params.get("offset"), 0, 0, 100_000),
        },
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/audit/logs/search", tags=["audit"])
async def search_audit_logs(request: Request) -> Any:
    """Proxy → Audit logs search."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/search",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/audit/logs/soc-timeline", tags=["audit"])
async def soc_timeline(request: Request) -> Any:
    """Proxy → Audit service SOC event feed (deny+kill+high-risk aggregation)."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/soc-timeline",
        params={"limit": _clamp_int(request.query_params.get("limit"), 60, 1, 200)},
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/policy/simulate", tags=["policy"])
async def simulate_policy(request: Request) -> Any:
    """Proxy → Policy service dry-run simulation."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.POLICY_SERVICE_URL.rstrip('/')}/policy/simulate",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/audit/logs/verify", tags=["audit"])
async def verify_audit_integrity(request: Request) -> Any:
    """Proxy → Audit logs integrity verification."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/verify",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# RISK PROXY — /risk
# P2-7 FIX: Correct downstream URLs (removed double /audit prefix)
# ─────────────────────────────────────────────────────────────

@app.get("/risk/summary", tags=["risk"])
async def risk_summary(request: Request) -> Any:
    """Proxy → Audit service summary for risk dashboard."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/risk/timeline", tags=["risk"])
async def risk_timeline(request: Request) -> Any:
    """Proxy → Audit service risk timeline. Forwards ?days= query param."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/risk/timeline",
        params={"days": _clamp_int(request.query_params.get("days"), 7, 1, 90)},
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/risk/top-threats", tags=["risk"])
async def risk_top_threats(request: Request) -> Any:
    """Proxy → Audit service top threats. Forwards ?limit= query param."""
    resp = await request.app.state.client.get(
        f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/risk/top-threats",
        params={"limit": _clamp_int(request.query_params.get("limit"), 10, 1, 100)},
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# DECISION PROXY — /decision
# NEW: Kill-switch and decision history routes proxied to Decision service
# ─────────────────────────────────────────────────────────────

@app.get("/decision/kill-switch/{tenant_id}", tags=["decision"])
async def get_kill_switch_status(tenant_id: str, request: Request) -> Any:
    """Proxy → Decision service kill-switch status."""
    resp = await request.app.state.client.get(
        f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/kill-switch/{tenant_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/decision/kill-switch/{tenant_id}", tags=["decision"])
async def toggle_kill_switch(tenant_id: str, request: Request) -> Any:
    """Proxy → Decision service toggle kill-switch."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/kill-switch/{tenant_id}",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.delete("/decision/kill-switch/{tenant_id}", tags=["decision"])
async def disengage_kill_switch(tenant_id: str, request: Request) -> Any:
    """Proxy → Decision service disengage kill-switch."""
    resp = await request.app.state.client.delete(
        f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/kill-switch/{tenant_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/decision/history", tags=["decision"])
async def decision_history(request: Request) -> Any:
    """Proxy → Decision service decision history."""
    resp = await request.app.state.client.get(
        f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/history",
        params={"limit": _clamp_int(request.query_params.get("limit"), 20, 1, 200)},
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/decision/summary", tags=["decision"])
async def decision_summary(request: Request) -> Any:
    """Proxy → Decision service risk summary (Redis-based counters)."""
    resp = await request.app.state.client.get(
        f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# FORENSICS PROXY — /forensics
# P0-3 FIX: FORENSICS_SERVICE_URL now exists in ACPSettings
# NEW: /forensics/replay/{agent_id} route added
# ─────────────────────────────────────────────────────────────

@app.get("/forensics/investigation", tags=["forensics"])
async def forensics_investigation(request: Request) -> Any:
    """Proxy → Forensics service investigation list."""
    resp = await request.app.state.client.get(
        f"{settings.FORENSICS_SERVICE_URL.rstrip('/')}/forensics/investigation",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/forensics/investigation/{agent_id}", tags=["forensics"])
async def get_investigation_report(agent_id: str, request: Request) -> Any:
    """Proxy → Forensics service investigation report for an agent."""
    resp = await request.app.state.client.get(
        f"{settings.FORENSICS_SERVICE_URL.rstrip('/')}/forensics/investigation/{agent_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/forensics/replay/{agent_id}", tags=["forensics"])
async def replay_agent_behavior(agent_id: str, request: Request) -> Any:
    """Proxy → Forensics service forensic replay for an agent."""
    resp = await request.app.state.client.get(
        f"{settings.FORENSICS_SERVICE_URL.rstrip('/')}/forensics/replay/{agent_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# BILLING PROXY — /billing
# ─────────────────────────────────────────────────────────────

@app.get("/billing/invoices", tags=["billing"])
async def billing_invoices(request: Request) -> Any:
    """Proxy → Usage service billing invoices."""
    resp = await request.app.state.client.get(
        f"{settings.USAGE_SERVICE_URL.rstrip('/')}/billing/invoices",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/billing/summary", tags=["billing"])
async def billing_summary(request: Request) -> Any:
    """Proxy → Usage service Redis-based billing ROI summary."""
    resp = await request.app.state.client.get(
        f"{settings.USAGE_SERVICE_URL.rstrip('/')}/billing/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/billing/events", tags=["billing"])
async def billing_record_event(request: Request) -> Any:
    """Proxy → Usage service billing events (records money saved)."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.USAGE_SERVICE_URL.rstrip('/')}/billing/events",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# USAGE PROXY — /usage
# ─────────────────────────────────────────────────────────────

@app.post("/usage/record", tags=["usage"])
async def usage_record(request: Request) -> Any:
    """Proxy → Usage service tool execution recording."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.USAGE_SERVICE_URL.rstrip('/')}/usage/record",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/usage/summary", tags=["usage"])
async def usage_summary(request: Request) -> Any:
    """Proxy → Usage service tenant usage summary."""
    resp = await request.app.state.client.get(
        f"{settings.USAGE_SERVICE_URL.rstrip('/')}/usage/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# API KEYS PROXY — /api-keys
# P0-5 FIX: Previously served by embedded router; now pure httpx proxy
# ─────────────────────────────────────────────────────────────

@app.get("/api-keys", tags=["API Keys"])
async def list_api_keys(request: Request) -> Any:
    """Proxy → API service list keys."""
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/api-keys",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/api-keys", tags=["API Keys"])
async def create_api_key(request: Request) -> Any:
    """Proxy → API service create key."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/api-keys",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.delete("/api-keys/{key_id}", tags=["API Keys"])
async def revoke_api_key(key_id: str, request: Request) -> Any:
    """Proxy → API service revoke key."""
    resp = await request.app.state.client.delete(
        f"{settings.API_SERVICE_URL.rstrip('/')}/api-keys/{key_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/api-keys/validate", tags=["API Keys"])
async def validate_api_key(request: Request) -> Any:
    """Proxy → API service validate key."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/api-keys/validate",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# INCIDENTS PROXY — /incidents
# ─────────────────────────────────────────────────────────────

@app.post("/incidents", tags=["Incidents"])
async def create_incident(request: Request) -> Any:
    """Proxy → API service create incident. Injects tenant_id from headers."""
    body = await request.json()
    body = dict(body)
    if "tenant_id" not in body:
        body["tenant_id"] = request.headers.get("X-Tenant-ID", "")

    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/incidents/summary", tags=["Incidents"])
async def incident_summary(request: Request) -> Any:
    """Proxy → API service incident summary (security score, MTTR, open counts)."""
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents/summary",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/incidents", tags=["Incidents"])
async def list_incidents(request: Request) -> Any:
    """Proxy → API service incident list with optional status/severity filters."""
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents",
        params={
            k: v for k, v in request.query_params.items()
            if k in ("status", "severity", "limit", "offset")
        },
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/incidents/{incident_id}", tags=["Incidents"])
async def get_incident(incident_id: str, request: Request) -> Any:
    """Proxy → API service single incident."""
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents/{incident_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.patch("/incidents/{incident_id}", tags=["Incidents"])
async def update_incident(incident_id: str, request: Request) -> Any:
    """Proxy → API service update incident status."""
    body = await request.json()
    resp = await request.app.state.client.patch(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents/{incident_id}",
        json=body,
        headers=_internal_headers(request),
    )
    result = resp.json()
    tenant_id_str = request.headers.get("X-Tenant-ID", "")
    if tenant_id_str and resp.status_code == 200:
        try:
            await redis.publish(
                f"acp:events:{tenant_id_str}",
                json.dumps({"type": "incident_updated", "data": result.get("data", {})}),
            )
        except Exception as _e:
            logger.debug("sse_publish_failed", event="incident_updated", error=str(_e))
    return result


@app.post("/incidents/{incident_id}/actions", tags=["Incidents"])
async def incident_action(incident_id: str, request: Request) -> Any:
    """Proxy → API service add response action to incident."""
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/incidents/{incident_id}/actions",
        json=body,
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# AUTONOMOUS RESPONSE ENGINE — /auto-response
# ─────────────────────────────────────────────────────────────

@app.post("/auto-response/rules", tags=["ARE"])
async def are_create_rule(request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/rules", tags=["ARE"])
async def are_list_rules(request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/rules/{rule_id}", tags=["ARE"])
async def are_get_rule(rule_id: str, request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.patch("/auto-response/rules/{rule_id}", tags=["ARE"])
async def are_update_rule(rule_id: str, request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.patch(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.delete("/auto-response/rules/{rule_id}", tags=["ARE"])
async def are_delete_rule(rule_id: str, request: Request) -> Any:
    resp = await request.app.state.client.delete(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}",
        headers=_internal_headers(request),
    )
    return Response(status_code=resp.status_code)


@app.post("/auto-response/toggle", tags=["ARE"])
async def are_toggle(request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/toggle",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/toggle", tags=["ARE"])
async def are_get_toggle(request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/toggle",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auto-response/simulate", tags=["ARE"])
async def are_simulate(request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/simulate",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/rules/{rule_id}/history", tags=["ARE"])
async def are_rule_history(rule_id: str, request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}/history",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auto-response/rules/{rule_id}/rollback/{version}", tags=["ARE"])
async def are_rollback(rule_id: str, version: int, request: Request) -> Any:
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}/rollback/{version}",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auto-response/rules/{rule_id}/feedback", tags=["ARE"])
async def are_feedback(rule_id: str, request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/rules/{rule_id}/feedback",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/metrics", tags=["ARE"])
async def are_metrics(request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/metrics",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/pending", tags=["ARE"])
async def are_list_pending(request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/pending",
        headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auto-response/pending/{approval_key}/approve", tags=["ARE"])
async def are_approve_pending(approval_key: str, request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/pending/{approval_key}/approve",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.post("/auto-response/replay", tags=["ARE"])
async def are_replay(request: Request) -> Any:
    body = await request.json()
    resp = await request.app.state.client.post(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/replay",
        json=body, headers=_internal_headers(request),
    )
    return resp.json()


@app.get("/auto-response/latency", tags=["ARE"])
async def are_latency(request: Request) -> Any:
    resp = await request.app.state.client.get(
        f"{settings.API_SERVICE_URL.rstrip('/')}/auto-response/latency",
        headers=_internal_headers(request),
    )
    return resp.json()


# ─────────────────────────────────────────────────────────────
# INSIGHTS PROXY — /insights
# ─────────────────────────────────────────────────────────────

@app.get("/insights/recent", tags=["risk"])
async def get_recent_insights(request: Request) -> dict:
    """Proxy → Insight service for recent AI analysis results."""
    resp = await request.app.state.client.get(
        f"{settings.INSIGHT_SERVICE_URL.rstrip('/')}/insights",
        params=request.query_params,
        headers=_internal_headers(request),
    )
    # Insight service returns {"success": true, "data": [...]} — pass through directly
    return resp.json()


# ─────────────────────────────────────────────────────────────
# DASHBOARD STATE — /dashboard/state
# Single aggregated endpoint: audit + agents + billing + insights + kill-switch
# ─────────────────────────────────────────────────────────────

@app.get("/dashboard/state", tags=["dashboard"])
async def dashboard_state(request: Request) -> dict[str, Any]:
    """
    Aggregated state for the executive dashboard.
    Fans out to audit, registry, usage, insight, and decision services concurrently.
    Each service failure returns an empty fallback — dashboard always loads.
    """
    client = request.app.state.client
    headers = _internal_headers(request)
    tenant_id = request.headers.get("X-Tenant-ID", "")

    async def _safe(url: str, params: dict | None = None) -> dict:
        try:
            resp = await client.get(url, headers=headers, params=params or {}, timeout=5.0)
            return resp.json() if resp.status_code < 500 else {}
        except Exception:
            return {}

    audit_r, agents_r, billing_r, insights_r = await asyncio.gather(
        _safe(f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/logs/summary"),
        _safe(f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents"),
        _safe(f"{settings.USAGE_SERVICE_URL.rstrip('/')}/usage/billing/summary"),
        _safe(f"{settings.INSIGHT_SERVICE_URL.rstrip('/')}/insights", {"limit": 5}),
    )

    kill_r: dict = {}
    if tenant_id:
        kill_r = await _safe(
            f"{settings.DECISION_SERVICE_URL.rstrip('/')}/decision/kill-switch/{tenant_id}"
        )

    agents_list = agents_r.get("data", agents_r) if isinstance(agents_r, dict) else []
    if not isinstance(agents_list, list):
        agents_list = []

    return {
        "success": True,
        "data": {
            "audit": audit_r.get("data", audit_r) if isinstance(audit_r, dict) else {},
            "agents": {
                "total": len(agents_list),
                "active": sum(
                    1 for a in agents_list
                    if str(a.get("status", "")).lower() == "active"
                ),
            },
            "billing": billing_r.get("data", billing_r) if isinstance(billing_r, dict) else {},
            "insights": insights_r.get("data", []) if isinstance(insights_r, dict) else [],
            "kill_switch": kill_r.get("data", kill_r) if isinstance(kill_r, dict) else {},
            "ts": int(time.time()),
        },
    }


# ─────────────────────────────────────────────────────────────
# SYSTEM HEALTH — /system/health
# Distributed health check: fan-out to all downstream services
# ─────────────────────────────────────────────────────────────

@app.get("/system/health", tags=["ops"])
async def system_health(request: Request) -> dict[str, Any]:
    """
    Aggregated health check across all ACP backend services.
    Each probe has a 4s timeout; overall response is always returned within ~5s.
    """
    client = request.app.state.client
    service_map = {
        "registry":  settings.REGISTRY_SERVICE_URL,
        "identity":  settings.IDENTITY_SERVICE_URL,
        "policy":    settings.POLICY_SERVICE_URL,
        "audit":     settings.AUDIT_SERVICE_URL,
        "usage":     settings.USAGE_SERVICE_URL,
        "behavior":  settings.BEHAVIOR_SERVICE_URL,
        "decision":  settings.DECISION_SERVICE_URL,
        "insight":   settings.INSIGHT_SERVICE_URL,
        "forensics": settings.FORENSICS_SERVICE_URL,
    }

    async def _probe(name: str, base_url: str) -> tuple[str, dict]:
        start = time.time()
        try:
            resp = await client.get(f"{base_url.rstrip('/')}/health", timeout=4.0)
            latency_ms = int((time.time() - start) * 1000)
            status = "healthy" if resp.status_code == 200 else "degraded"
            return name, {"status": status, "latency_ms": latency_ms}
        except Exception as exc:
            latency_ms = int((time.time() - start) * 1000)
            return name, {"status": "unreachable", "latency_ms": latency_ms, "error": str(exc)[:80]}

    results = await asyncio.gather(*[_probe(n, u) for n, u in service_map.items()])
    services = dict(results)

    healthy_count = sum(1 for s in services.values() if s["status"] == "healthy")
    total = len(services)
    overall = "healthy" if healthy_count == total else ("degraded" if healthy_count > 0 else "down")

    return {
        "status": overall,
        "healthy": healthy_count,
        "total": total,
        "services": services,
        "gateway": {"status": "healthy", "latency_ms": 0},
        "ts": int(time.time()),
    }

# ─────────────────────────────────────────────────────────────
# EXECUTION PROXY — /execute
# ─────────────────────────────────────────────────────────────

@app.post("/execute", tags=["execution"])
@app.post("/execute/{tool_name}", tags=["execution"])
async def execute_tool(request: Request, tool_name: str | None = None) -> Any:
    """
    Tool execution endpoint. Decision has already been evaluated by SecurityMiddleware.
    Proxies to the Policy service for final execution and auditing.
    """
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID", str(uuid.uuid4()))
    agent_id_str = request.headers.get("X-Agent-ID", "")
    tenant_id_str = request.headers.get("X-Tenant-ID", "")
    
    # Extract tool from path or body
    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        pass
    
    tool = tool_name or body.get("tool", "") or request.headers.get("X-ACP-Tool", "unknown")

    # 1. Prepare internal headers and body
    headers = _internal_headers(request)
    headers["X-Request-ID"] = request_id
    if agent_id_str:
        headers["X-Agent-ID"] = agent_id_str
    if tenant_id_str:
        headers["X-Tenant-ID"] = tenant_id_str
    
    # Pass the decision metadata to the backend service
    decision = getattr(request.state, "decision", None)
    if decision:
        body["_decision"] = {
            "action": decision.action.value if hasattr(decision.action, "value") else str(decision.action),
            "risk": getattr(decision, "risk", 0.0),
            "confidence": getattr(decision, "confidence", 1.0),
            "reasons": [str(r) for r in (getattr(decision, "reasons", None) or [])],
            "signals": getattr(decision, "signals", {}) or {},
        }
    
    # 2. Proxy request to Policy service
    client: httpx.AsyncClient = request.app.state.client
    try:
        resp = await client.post(
            f"{settings.POLICY_SERVICE_URL.rstrip('/')}/policy/execute",
            json=body,
            headers=headers,
            timeout=10.0
        )
        
        if resp.status_code != 200:
            logger.error("policy_execution_failed", status_code=resp.status_code, text=resp.text)
            try:
                return resp.json()
            except Exception:
                raise HTTPException(status_code=502, detail="Policy service execution failed")
                
        result = resp.json()
        data = result.get("data") if result.get("success") and "data" in result else result
        
        # 3. Publish tool_executed event to SSE bus
        if tenant_id_str:
            action_val = data.get("action", "allow")
            try:
                await redis.publish(
                    f"acp:events:{tenant_id_str}",
                    json.dumps({
                        "type": "tool_executed",
                        "data": {
                            "request_id": request_id,
                            "agent_id": agent_id_str,
                            "tool": tool,
                            "action": action_val,
                            "risk": data.get("risk", 0.0),
                            "confidence": data.get("confidence", 1.0),
                            "signals": data.get("signals", {}),
                            "reasons": (data.get("reasons") or [])[:3],
                            "ts": int(time.time()),
                        },
                    }),
                )
            except Exception as _e:
                logger.debug("sse_publish_failed", event="tool_executed", error=str(_e))

        return result

    except Exception as exc:
        logger.error("gateway_proxy_error", error=str(exc))
        raise HTTPException(status_code=502, detail="Service unavailable")


# ─────────────────────────────────────────────────────────────
# SSE EVENT STREAM — /events/stream
# Real-time per-tenant event bus via Server-Sent Events + Redis Pub/Sub
# ─────────────────────────────────────────────────────────────

@app.get("/events/stream", tags=["events"])
async def events_stream(request: Request) -> StreamingResponse:
    """
    Server-Sent Events stream for real-time UI synchronization.
    Auth is handled inline (endpoint is in _SKIP_PATHS, bypasses SecurityMiddleware).
    Uses PubSubManager: one Redis subscription per tenant channel, fan-out to
    per-client bounded queues (maxsize=100). Old clients are not blocked by slow ones.
    """
    token = request.cookies.get("acp_token")
    if not token:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr[7:].strip()

    if not token:
        return Response(status_code=401, content='{"error":"Unauthorized"}', media_type="application/json")

    try:
        payload = await asyncio.to_thread(token_validator.validate, token)
        tenant_id_str: str = payload.get("tenant_id", "")
        if not tenant_id_str:
            return Response(status_code=401, content='{"error":"Missing tenant claim"}', media_type="application/json")
    except Exception:
        return Response(status_code=401, content='{"error":"Invalid token"}', media_type="application/json")

    channel = f"acp:events:{tenant_id_str}"

    async def event_generator() -> AsyncIterator[str]:
        q = await pubsub_manager.subscribe(channel)
        try:
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'tenant_id': tenant_id_str})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield f"event: heartbeat\ndata: {json.dumps({'ts': int(time.time())})}\n\n"
        finally:
            await pubsub_manager.unsubscribe(channel, q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
