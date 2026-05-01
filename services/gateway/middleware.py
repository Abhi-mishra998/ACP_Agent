"""
ACP Gateway — Security Middleware
==================================
Enforces the complete request pipeline:

  Request
    ↓ 0. Kill Switch   — tenant emergency blockade check
    ↓ 1. Auth          — local JWT + SHA-256 revocation + jti check
    ↓ 2. Rate Limit    — Redis Lua atomic per-token + per-agent
    ↓ 3. Inference     — injection detection, tool guard, risk scoring
    ↓ 4. Policy        — Redis cache → OPA (cache miss only)
    ↓ 5. Behavior      — sequence, velocity, cost, cross-agent intelligence
    ↓ 6. Decision      — unified DecisionEngine (ONE formula, ONE threshold table)
    ↓ 7. Enforcement   — ALLOW/MONITOR/THROTTLE/ESCALATE/KILL
    ↓ 8. Execution     — call_next(request)
    ↓ 9. Output Filter — redact secrets from response
    ↓ 10. Audit        — async Redis Stream (non-blocking)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import redis.exceptions
import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware

from sdk.common.config import settings
from sdk.common.exceptions import ACPAuthError, ACPError
from sdk.common.ratelimit import RateLimiter
from sdk.utils import IDEMPOTENCY_HITS_TOTAL, RATE_LIMIT_EXCEEDED_TOTAL
from services.decision.schemas import Decision, ExecutionAction
from services.gateway.auth import REDIS_REVOKE_PREFIX, token_validator
from services.gateway.client import service_client
from services.gateway.inference_proxy import inference_proxy

logger = structlog.get_logger(__name__)


async def _safe_bg(coro) -> None:
    """Wrapper for fire-and-forget tasks — prevents unhandled exception noise."""
    try:
        await coro
    except Exception as _exc:
        logger.warning("background_task_failed", error=str(_exc))


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

_SKIP_PATHS = frozenset(
    [
        "/health", "/docs", "/openapi.json", "/redoc", "/metrics",
        "/auth/token", "/auth/login", "/auth/agent/token",  # public auth endpoints
        "/events/stream",  # SSE — inline auth handled in the route handler
    ]
)

# Management paths: require auth + rate-limiting, but bypass the agent
# tool-execution security pipeline (OPA policy + Decision Engine).
# These are internal CRUD endpoints for human admin/SOC operators.
_MANAGEMENT_PATH_PREFIXES = (
    "/agents",
    "/logs",
    "/audit",
    "/decision",
    "/insights",
    "/forensics",
    "/usage",
    "/billing",
    "/incidents",
    "/metrics",
    "/risk",
    "/stream",
    "/auto-response",
    "/api-keys",
    "/system",
    "/auth",
)

# Configuration from global settings
_GLOBAL_RATE_LIMIT = settings.GLOBAL_RATE_LIMIT
_IP_RATE_LIMIT = settings.IP_RATE_LIMIT
_TENANT_RATE_LIMIT = settings.TENANT_RATE_LIMIT
_AGENT_RATE_LIMIT = settings.AGENT_RATE_LIMIT
_TOKEN_RATE_LIMIT = settings.TOKEN_RATE_LIMIT
_RATE_WINDOW = 60  # seconds

_IDEMPOTENCY_TTL_MAP = {
    "enterprise": 86400,  # 24 hours
    "premium": 3600,  # 1 hour
    "basic": 300,  # 5 minutes
}
_IDEMPOTENCY_PREFIX = "acp:idempotency:"
_GLOBAL_SLA_BUDGET = 2.0  # seconds — caps P99 at ~2s; fail-fast beats retrying into a dead downstream


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Single-pass security enforcement for all ACP Gateway requests.
    Enforces:
    1. Global/IP Rate Limiting
    2. Idempotency (Post-Auth)
    3. Hierarchical Rate Limiting (Tenant/Agent/Token)
    4. Inference Proxy & OPA Policy
    5. Output Redaction
    6. Audit Logging
    """

    def __init__(self, app: FastAPI, redis: Redis) -> None:
        super().__init__(app)
        self.redis = redis
        self.limiter = RateLimiter(redis)
        self.semaphore = asyncio.Semaphore(500)  # Backpressure: cap concurrent requests
        service_client.set_redis(redis)

    async def _authenticate(
        self, request: Request, is_execute_path: bool = False
    ) -> tuple[uuid.UUID, uuid.UUID, str, str, str | None]:
        """
        Authenticate the request and return
        (tenant_id, agent_id, tenant_id_str, agent_id_str, jti).
        """
        auth_header = request.headers.get("Authorization")
        x_cookie_token = request.cookies.get("acp_token")
        api_key = request.headers.get("X-API-Key")
        client_ip = request.client.host if request.client else "unknown"

        if not auth_header and x_cookie_token:
            auth_header = f"Bearer {x_cookie_token}"

        tenant_id: uuid.UUID | None = None
        agent_id: uuid.UUID | None = None
        tenant_id_str: str = ""
        agent_id_str: str = ""
        jti: str | None = None

        # Rate limit failed auth attempts per IP
        auth_fail_key = f"acp:auth_failures:{client_ip}"

        if auth_header and auth_header.lower().startswith("bearer "):
            parts = auth_header.split(" ", 1)
            if len(parts) == 2:
                token = parts[1].strip()
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                if await self.redis.get(f"{REDIS_REVOKE_PREFIX}{token_hash}"):
                    await self.redis.incr(auth_fail_key)
                    await self.redis.expire(auth_fail_key, 300)
                    failures = await self.redis.get(auth_fail_key)
                    if failures and int(failures) > 10:  # 10 failed auths per 5min
                        raise HTTPException(status_code=429, detail="Too many authentication failures")
                    raise HTTPException(status_code=401, detail="Token revoked")

                try:
                    auth_data = token_validator.validate(token)
                except Exception as exc:
                    await self.redis.incr(auth_fail_key)
                    await self.redis.expire(auth_fail_key, 300)
                    failures = await self.redis.get(auth_fail_key)
                    if failures and int(failures) > 10:
                        raise HTTPException(status_code=429, detail="Too many authentication failures")
                    
                    # Propagate the actual error message (e.g. "Token has expired")
                    # instead of masking it with generic "Invalid token".
                    detail = str(exc) if isinstance(exc, ACPAuthError) else "Invalid token"
                    raise HTTPException(status_code=401, detail=detail)

                # Active RBAC Mapping
                role = auth_data.get("role", "VIEWER")
                permissions_map = {
                    "ADMIN": ["*"],
                    "SECURITY": ["kill_switch", "view_risk", "execute_agent"],
                    "AUDITOR": ["view_risk", "view_audit"],
                    "VIEWER": ["view_risk"],
                    "agent": ["execute_agent"],
                }
                request.state.permissions = permissions_map.get(role, [])
                request.state.role = role

                # Write-path enforcement: mutations require ADMIN or SECURITY,
                # except agent-role tokens on /execute (controlled by OPA + Decision Engine).
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    if role not in ("ADMIN", "SECURITY"):
                        if not (is_execute_path and role == "agent"):
                            raise HTTPException(
                                status_code=403,
                                detail="Write operations require ADMIN or SECURITY role",
                            )

                # Enterprise JTI Atomic Burst Lock — tool executions only.
                # Management CRUD paths are already protected by RBAC and rate limiting.
                # Replay detection only applies to /execute (tool execution) where the
                # same JTI reusing within 50ms would indicate a genuine replay attack.
                jti = auth_data.get("jti")
                if jti and is_execute_path and request.method not in ("GET", "HEAD", "OPTIONS"):
                    if await self.redis.get(f"{REDIS_REVOKE_PREFIX}jti:{jti}"):
                        raise HTTPException(status_code=401, detail="Token ID revoked")

                    replay_key = f"acp:jti_last_used:{jti}"
                    now_ts = time.time()

                    try:
                        if not await self.redis.setnx(replay_key, now_ts):
                            last = await self.redis.get(replay_key)
                            if last and (now_ts - float(last)) < 0.05:  # 50ms burst window
                                raise HTTPException(status_code=429, detail="Too many requests: burst replay detected")
                            await self.redis.set(replay_key, now_ts)

                        # Replay TTL aligned with Token Expiry
                        exp = auth_data.get("exp")
                        ttl = int(exp - now_ts) if exp else 900
                        await self.redis.expire(replay_key, max(1, ttl))
                    except HTTPException:
                        raise  # propagate real replay rejections
                    except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as _re:
                        # Redis unavailable → skip replay check; genuine replays are still
                        # caught by JTI revocation above. False-blocking valid traffic is worse.
                        logger.warning("replay_check_skipped_redis_unavailable", jti=jti, error=str(_re))

                agent_id_str = auth_data.get("agent_id", "")
                request.state.actor = auth_data.get("sub", "unknown")
                tenant_id_str = auth_data["tenant_id"]
                
                try:
                    tenant_id = uuid.UUID(tenant_id_str)
                    agent_id = uuid.UUID(agent_id_str) if agent_id_str else uuid.UUID(int=0)
                except ValueError:
                    raise HTTPException(status_code=401, detail="Invalid identity claims in token")

                # Store full JWT claims so downstream code can use embedded permissions
                # without making any Registry or Policy HTTP calls.
                request.state.jwt_claims = auth_data
        elif api_key:
            key_data = await service_client.validate_api_key(api_key)
            if key_data:
                tenant_id_str = key_data["tenant_id"]
                tenant_id = uuid.UUID(tenant_id_str)
                agent_id = uuid.UUID(int=0)

        if not tenant_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        x_tenant = request.headers.get("X-Tenant-ID")
        if not x_tenant:
            raise HTTPException(status_code=401, detail="Tenant ID required")

        if x_tenant != tenant_id_str:
            logger.critical("tenant_isolation_violation", token_tenant=tenant_id_str, header_tenant=x_tenant)
            raise HTTPException(status_code=403, detail="Tenant mismatch detected")

        # Org-level isolation: if the client sends X-Org-ID it MUST match the token's org_id.
        # The header is optional — older clients without org_id support are still served.
        x_org_id = request.headers.get("X-Org-ID")
        if x_org_id and auth_header:
            token_org_id = (
                (request.state.jwt_claims if hasattr(request.state, "jwt_claims") else {})
                .get("org_id", tenant_id_str)
            )
            if x_org_id != token_org_id:
                logger.critical(
                    "org_isolation_violation",
                    token_org=token_org_id,
                    header_org=x_org_id,
                )
                raise HTTPException(status_code=403, detail="Org mismatch detected")
        
        # Enforce strict SaaS invariant: org_id == tenant_id on ALL write paths
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            org_to_check = x_org_id or ((request.state.jwt_claims if hasattr(request.state, "jwt_claims") else {}).get("org_id"))
            if org_to_check:
                from sdk.common.invariants import assert_org_consistency, InvariantViolation
                try:
                    assert_org_consistency(uuid.UUID(org_to_check), tenant_id, "gateway write path")
                except InvariantViolation as e:
                    logger.critical("strict_invariant_violation", detail=str(e))
                    raise HTTPException(status_code=403, detail=str(e))

        return tenant_id, agent_id or uuid.UUID(int=0), tenant_id_str, agent_id_str, jti

    async def _check_idempotency(
        self, request: Request, tenant_id_str: str, body_hash: str
    ) -> Response | None:
        """Check for idempotency hit. Returns a Response if hit, else None."""
        idem_key = request.headers.get("Idempotency-Key")
        if not (idem_key and request.method in ("POST", "PUT", "PATCH")):
            return None

        full_key = f"{_IDEMPOTENCY_PREFIX}{tenant_id_str}:{idem_key}"
        cached = await self.redis.get(full_key)
        if not cached:
            return None

        cached_data = json.loads(cached)
        if cached_data.get("payload_hash") != body_hash:
            IDEMPOTENCY_HITS_TOTAL.labels(
                tenant_id=tenant_id_str, outcome="conflict"
            ).inc()
            return self._deny(
                "Idempotency conflict: key used with different payload", 400
            )

        logger.info("idempotency_hit", key=idem_key)
        IDEMPOTENCY_HITS_TOTAL.labels(tenant_id=tenant_id_str, outcome="hit").inc()
        return Response(
            content=cached_data["body"],
            status_code=cached_data["status"],
            headers={**cached_data["headers"], "X-Idempotency-Hit": "true"},
            media_type="application/json",
        )

    async def _check_rate_limits(
        self,
        tenant_id_str: str,
        agent_id: uuid.UUID,
        jti: str | None,
        tier: str,
        rpm_limit: int = 0,
    ) -> None:
        """
        Check tenant, agent, and token rate limits.
        rpm_limit: real per-minute limit from the Tenant record (0 = use config default).
        """
        effective_tenant_limit = rpm_limit if rpm_limit > 0 else _TENANT_RATE_LIMIT
        if not await self.limiter.check_limit(
            f"acp:ratelimit:tenant:{tenant_id_str}",
            effective_tenant_limit,
            _RATE_WINDOW,
            tier=tier,
        ):
            RATE_LIMIT_EXCEEDED_TOTAL.labels(layer="tenant", tier=tier).inc()
            raise HTTPException(status_code=429, detail="Tenant rate limit exceeded")

        if not await self.limiter.check_limit(
            f"acp:ratelimit:agent:{tenant_id_str}:{str(agent_id)}",
            _AGENT_RATE_LIMIT,
            _RATE_WINDOW,
            tier=tier,
            check_pool=False,
        ):
            RATE_LIMIT_EXCEEDED_TOTAL.labels(layer="agent", tier=tier).inc()
            raise HTTPException(status_code=429, detail="Agent rate limit exceeded")

        if not await self.limiter.check_token_limit(
            jti, str(agent_id), _TOKEN_RATE_LIMIT, _RATE_WINDOW, tier=tier, check_pool=False
        ):
            RATE_LIMIT_EXCEEDED_TOTAL.labels(layer="token", tier=tier).inc()
            raise HTTPException(status_code=429, detail="Token rate limit exceeded")

    async def _check_early_defense(self, client_ip: str) -> Response | None:
        """Global and IP-based rate limiting."""
        if not await self.limiter.check_limit(
            "acp:ratelimit:global", _GLOBAL_RATE_LIMIT, _RATE_WINDOW, check_pool=False
        ):
            RATE_LIMIT_EXCEEDED_TOTAL.labels(layer="global", tier="none").inc()
            return self._deny("System-wide rate limit reached", 429)

        if not await self.limiter.check_limit(
            f"acp:ratelimit:ip:{client_ip}", _IP_RATE_LIMIT, _RATE_WINDOW, check_pool=False
        ):
            RATE_LIMIT_EXCEEDED_TOTAL.labels(layer="ip", tier="none").inc()
            return self._deny("IP-based rate limit exceeded", 429)
        return None

    def _get_tool_name(self, request: Request) -> str:
        """Extract tool name from headers or path."""
        tool_name = request.headers.get("X-ACP-Tool")
        if not tool_name:
            path_parts = request.url.path.strip("/").split("/")
            if len(path_parts) >= 2 and path_parts[0] == "execute":
                tool_name = path_parts[1]
            else:
                tool_name = "unknown-tool"
        return tool_name

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        async with self.semaphore:
            return await self._dispatch_with_resilience(request, call_next)

    async def _dispatch_with_resilience(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.time()
        structlog.contextvars.clear_contextvars()

        # 1. Initialize Request ID and SLA Deadline budget
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        deadline = start_time + _GLOBAL_SLA_BUDGET

        self._init_context(request, request_id, deadline)

        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        try:
            # STEP 0 — EARLY SYSTEM DEFENSE (inside try so Redis errors are caught)
            defense_resp = await self._check_early_defense(client_ip)
            if defense_resp:
                return defense_resp

            # Phase 1: Authentication & Identity
            identity = await self._handle_auth_phase(request)
            tenant_id, agent_id, t_id_str, tier = identity


            # Phase 2: Input Protections (Idempotency + Rate Limiting)
            if time.time() > deadline:
                return self._deny("SLA Budget Exhausted (Input Phase)", 504)

            input_check = await self._handle_input_phase(
                request, t_id_str, agent_id, tier
            )
            body_hash, jti = input_check
            if isinstance(body_hash, Response):
                return body_hash

            # ── MANAGEMENT FAST PATH ──────────────────────────────────────────
            # Admin/SOC CRUD endpoints (agents, audit logs, kill-switch, etc.)
            # skip the agent tool-execution pipeline (OPA + Decision Engine).
            # Auth, tenant isolation, RBAC, and rate limiting are already enforced above.
            is_management = any(
                request.url.path.startswith(p) for p in _MANAGEMENT_PATH_PREFIXES
            )

            if is_management:
                response = await call_next(request)
                response.headers["X-Trace-ID"] = getattr(request.state, "trace_id", "")
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["X-Content-Type-Options"] = "nosniff"
                self._log_audit(
                    t_id_str, agent_id, "management_api",
                    request.url.path, "allow", None, request_id,
                    {"method": request.method, "status": response.status_code}
                )
                return response
            # ── END MANAGEMENT FAST PATH ──────────────────────────────────────

            # 🚨 HARD KILL SWITCH (Economic / Security Blockade)
            # Checked AFTER management bypass to allow admins to disengage the lock.
            if await self.redis.get(f"acp:tenant_kill:{t_id_str}"):
                return JSONResponse(status_code=403, content={
                    "error": "Tenant blocked due to security violation"
                })


            tool_name = self._get_tool_name(request)

            # Explicit RBAC Evaluation mapped to Intent Action
            perms = getattr(request.state, "permissions", [])
            if "*" not in perms and "execute_agent" not in perms:
                if tool_name != "unknown-tool":
                    return self._deny(f"Permission denied: execute_agent ({tool_name})", 403)

            # Phase 3: Security, Behavior, and Policy Signal Collection
            remaining = deadline - time.time()
            if remaining <= 0:
                return self._deny("SLA Budget Exhausted (Security Phase)", 504)
            try:
                proxy_res = await asyncio.wait_for(
                    self._handle_security_phase(
                        request, tool_name, tenant_id, agent_id, t_id_str, request_id
                    ),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return self._deny("SLA Budget Exhausted (Security Phase)", 504)
            if isinstance(proxy_res, Response):
                return proxy_res

            # Phase 4: Decision Engine Orchestration (The Brain)
            # Pass agent JWT claims to decision service to eliminate Registry call there
            jwt_claims  = getattr(request.state, "jwt_claims", {}) or {}
            agent_claims_payload = None
            if jwt_claims.get("agent_status") is not None:
                import json as _json
                agent_claims_payload = _json.dumps({
                    "status":      jwt_claims["agent_status"],
                    "permissions": jwt_claims.get("permissions", []),
                    "risk_level":  jwt_claims.get("risk_level", "low"),
                })

            req_data = {
                "tenant_id":      str(tenant_id),
                "agent_id":       str(agent_id),
                "tool":           tool_name,
                "tokens":         proxy_res.metadata.get("tokens", 0),
                "inference_risk": proxy_res.risk_score,
                "inference_flags": proxy_res.flags,
                "request_id":     request_id,
                "payload_hash":   proxy_res.prompt_hash,
                "client_ip":      client_ip,
                "metadata":       {"agent_claims": agent_claims_payload} if agent_claims_payload else {},
            }

            remaining = deadline - time.time()
            if remaining <= 0:
                return self._deny("SLA Budget Exhausted (Decision Phase)", 504)
            try:
                decision_data = await asyncio.wait_for(
                    service_client.evaluate_decision(req_data),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                logger.error("decision_engine_timeout_fail_closed")
                return self._deny("Fail-Closed: Decision engine timed out", 403)
            except Exception as _dec_exc:
                logger.error("decision_engine_unavailable_fail_closed", error=str(_dec_exc))
                return self._deny("Fail-Closed: Decision engine unavailable", 403)
            decision = Decision(**(decision_data or {"action": "allow", "risk": 0.0}))
            request.state.decision = decision

            # Phase 11: Alerting
            if decision.risk > 0.9:
                logger.critical("critical_threat_detected", tenant_id=t_id_str, agent_id=str(agent_id), score=decision.risk)
                asyncio.create_task(_safe_bg(self.redis.incr("acp:metrics:threat_count")))

            # Record ROI / money saved to Usage service — truly fire-and-forget
            asyncio.create_task(_safe_bg(service_client.record_billing_event(
                tenant_id=t_id_str,
                action=decision.action.value,
                agent_id=str(agent_id),
            )))

            # 5. Enforcement — map action to response
            if decision.action == ExecutionAction.KILL:
                auth_header = request.headers.get("Authorization", "")
                _kill_token = auth_header.split(" ", 1)[1].strip() if " " in auth_header else auth_header
                token_hash = hashlib.sha256(_kill_token.encode()).hexdigest()

                revoke_key = f"{REDIS_REVOKE_PREFIX}{token_hash}"
                await self.redis.setex(revoke_key, 86400, "killed")

                jti = getattr(request.state, "jti", None)
                if jti:
                    await self.redis.setex(f"{REDIS_REVOKE_PREFIX}jti:{jti}", 86400, "killed")

                asyncio.create_task(_safe_bg(self.redis.incr("acp:metrics:token_failures")))
                asyncio.create_task(_safe_bg(self.redis.incr("acp:metrics:kill_switch_events")))

                self._log_decision(t_id_str, agent_id, tool_name, decision, request_id)
                return self._deny(
                    f"Security: Agent TERMINATED. Reasons: {', '.join(decision.reasons)}", 403
                )

            if decision.action in (ExecutionAction.DENY,):
                self._log_decision(t_id_str, agent_id, tool_name, decision, request_id)
                return self._deny(
                    f"Security: Request Blocked. Reasons: {', '.join(decision.reasons)}", 403
                )

            if decision.action == ExecutionAction.ESCALATE:
                self._log_decision(t_id_str, agent_id, tool_name, decision, request_id)
                return self._escalate(
                    f"Action escalated for forensic review. Reasons: {', '.join(decision.reasons)}"
                )

            if decision.action == ExecutionAction.THROTTLE:
                await asyncio.sleep(0.5)  # signal back-pressure without burning the SLA budget

            # Emit to Groq intelligence queue (non-blocking, best-effort)
            asyncio.create_task(_safe_bg(self._emit_groq_event(
                request_id, t_id_str, str(agent_id), tool_name, decision
            )))

            # Phase 6: Execution & Output Filtering
            response = await call_next(request)

            # Enforce Secure Headers & Tracing
            response.headers["X-Trace-ID"] = getattr(request.state, "trace_id", "")
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

            # Application-level redaction
            if (
                decision.action == ExecutionAction.REDACT or
                "pii_detected" in proxy_res.flags
            ):
                response = await self._filter_response(response)

            await self._finalize_request(
                request,
                response,
                t_id_str,
                agent_id,
                tool_name,
                body_hash,
                tier,
                start_time,
                request_id,
                proxy_res.risk_score,
            )
            return response

        except HTTPException as e:
            return self._deny(e.detail, e.status_code)
        except ACPError as e:
            return self._deny(e.message, e.status_code)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as exc:
            logger.critical("redis_circuit_breaker_tripped", error=str(exc))
            return self._deny("Fail-Closed: Security infrastructure unavailable", 503)
        except Exception as exc:
            logger.exception("gateway_unhandled_error", error=str(exc))
            return self._deny("Internal Server Error", 500)

    async def _handle_auth_phase(
        self, request: Request
    ) -> tuple[uuid.UUID, uuid.UUID, str, str]:
        """Verify identity and bind context."""
        is_execute = request.url.path.startswith("/execute")
        tenant_info = await self._authenticate(request, is_execute_path=is_execute)
        tenant_id, agent_id, t_id_str, _, jti = tenant_info
        request.state.jti = jti

        # On the execute path, if the caller is an admin (agent_id == UUID(0))
        # and an explicit X-Agent-ID is provided, use that agent's context so
        # the security pipeline evaluates the SELECTED agent's permissions — not
        # a wildcard-admin override.  This makes attack simulation accurate.
        request.state.agent_via_header = False
        if is_execute and agent_id == uuid.UUID(int=0):
            x_agent_hdr = request.headers.get("X-Agent-ID", "").strip()
            if x_agent_hdr:
                try:
                    agent_id = uuid.UUID(x_agent_hdr)
                    request.state.agent_via_header = True
                except ValueError:
                    pass

        tenant_meta = await service_client.get_tenant_metadata(tenant_id)
        tier: str = tenant_meta.get("tier", "basic")
        rpm_limit: int = int(tenant_meta.get("rpm_limit", 0))
        request.state.tier = tier
        request.state.rpm_limit = rpm_limit

        structlog.contextvars.bind_contextvars(
            tenant_id=t_id_str, agent_id=str(agent_id), tier=tier, actor=getattr(request.state, "actor", "unknown")
        )
        request.state.tenant_id = tenant_id
        request.state.agent_id = agent_id
        return tenant_id, agent_id, t_id_str, tier

    async def _handle_input_phase(
        self, request: Request, t_id_str: str, agent_id: uuid.UUID, tier: str
    ) -> tuple[str, str | None] | Response:
        """Handle idempotency and rate limiting."""
        raw_body = await request.body()
        body_hash = hashlib.sha256(raw_body).hexdigest() if raw_body else "empty"

        idem_resp = await self._check_idempotency(request, t_id_str, body_hash)
        if idem_resp:
            return idem_resp

        jti      = getattr(request.state, "jti", None)
        rpm_limit = getattr(request.state, "rpm_limit", 0)
        await self._check_rate_limits(t_id_str, agent_id, jti, tier, rpm_limit=rpm_limit)
        return body_hash, jti

    async def _handle_security_phase(
        self,
        request: Request,
        tool_name: str,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        t_id_str: str,
        request_id: str,
    ) -> float | Response:
        """Run Inference Proxy and OPA policy."""
        raw_body   = await request.body()
        jwt_claims = getattr(request.state, "jwt_claims", None)
        agent_meta = await service_client.get_agent_metadata(agent_id, tenant_id, jwt_claims=jwt_claims)
        allowed_tools = self._extract_allowed_tools(agent_meta)

        # ADMIN Override: grant wildcard only when admin is NOT targeting a specific
        # agent via X-Agent-ID (attack simulation, playground).  When agent_via_header
        # is True the selected agent's real permissions are enforced so the pipeline
        # tests actual policy, not a blanket bypass.
        user_perms = getattr(request.state, "permissions", [])
        if "*" in user_perms and not getattr(request.state, "agent_via_header", False):
            if allowed_tools is None:
                allowed_tools = ["*"]
            elif "*" not in allowed_tools:
                allowed_tools.append("*")

        proxy_result = await self._run_inference_proxy(
            request, raw_body, tool_name, allowed_tools, tenant_id, agent_id
        )
        if not proxy_result.allowed:
            self._log_block(t_id_str, agent_id, tool_name, proxy_result, request_id)
            return self._deny(
                f"Security: {proxy_result.reason}", proxy_result.status_code
            )

        return proxy_result

    def _init_context(self, request: Request, request_id: str, deadline: float) -> None:
        """Initialize request state and context metadata."""
        request.state.deadline = deadline
        request.state.request_id = request_id

        trace_id = request.headers.get("X-Trace-ID", request_id)
        request.state.trace_id = trace_id
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")

        request.state.tenant_id = None
        request.state.tier = "basic"
        structlog.contextvars.bind_contextvars(request_id=request_id, trace_id=trace_id, deadline=deadline, client_ip=client_ip, user_agent=user_agent)

    def _extract_allowed_tools(self, agent_meta: dict | None) -> list[str] | None:
        """Extract allowed tool list from agent metadata."""
        if not agent_meta:
            return None
        return [
            p["tool_name"]
            for p in agent_meta.get("permissions", [])
            if str(p.get("action", "")).upper() == "ALLOW"
        ]

    async def _run_inference_proxy(
        self,
        request: Request,
        raw_body: bytes,
        tool_name: str,
        allowed_tools: list[str] | None,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> Any:  # noqa: ANN401
        """Execute inference proxy checks."""
        x_tenant_header = request.headers.get("X-Tenant-ID")
        try:
            request_tenant_id = (
                uuid.UUID(x_tenant_header) if x_tenant_header else tenant_id
            )
        except (ValueError, TypeError):
            request_tenant_id = tenant_id

        return inference_proxy.check_input(
            raw_body=raw_body,
            content_type=request.headers.get("content-type", ""),
            tool_name=tool_name,
            allowed_tools=allowed_tools,
            request_tenant_id=request_tenant_id,
            token_tenant_id=tenant_id,
            agent_id=agent_id,
        )

    def _log_block(
        self, tenant_id: str, agent_id: uuid.UUID, tool: str, res: Any, request_id: str
    ) -> None:
        """Log a security block to the audit stream."""
        meta = {
            **res.metadata,
            "risk_score": res.risk_score,
            "flags": res.flags,
            "prompt_hash": res.prompt_hash,
        }
        self._log_audit(
            tenant_id,
            agent_id,
            "inference_proxy_block",
            tool,
            "deny",
            res.reason,
            request_id,
            meta,
        )

    async def _finalize_request(
        self,
        request: Request,
        response: Response,
        t_id: str,
        a_id: uuid.UUID,
        tool: str,
        b_hash: str,
        tier: str,
        start: float,
        req_id: str,
        risk: float,
    ) -> None:
        """Handle post-execution caching, metrics, and auditing."""
        # Idempotency Cache
        idem_key = request.headers.get("Idempotency-Key")
        if idem_key and response.status_code < 500:
            await self._cache_idempotency(t_id, idem_key, response, b_hash, tier)

        # SLO & Audit
        self._record_slo(request, start, response.status_code)
        meta = {"status": response.status_code, "risk_score": risk}
        self._log_audit(t_id, a_id, "execute_tool", tool, "allow", None, req_id, meta)

    def _log_audit(
        self,
        tenant_id: str,
        agent_id: uuid.UUID,
        action: str,
        tool: str,
        decision: str,
        reason: str | None,
        request_id: str,
        meta: dict[str, Any],
    ) -> None:
        ctx = structlog.contextvars.get_contextvars()
        meta["actor"] = ctx.get("actor", "unknown")
        meta["trace_id"] = ctx.get("trace_id", request_id)

        async def _safe_log():
            try:
                await service_client.log_audit_stream(
                    self.redis,
                    {
                        "tenant_id": tenant_id,
                        "agent_id": str(agent_id),
                        "action": action,
                        "tool": tool,
                        "decision": decision,
                        "reason": reason,
                        "request_id": request_id,
                        "metadata_json": json.dumps(meta),
                    },
                )
            except Exception as e:
                logger.error("background_audit_log_failed", error=str(e), request_id=request_id)

        asyncio.create_task(_safe_bg(_safe_log()))

    async def _cache_idempotency(
        self, tenant_id: str, key: str, response: Response, body_hash: str, tier: str
    ) -> None:
        full_key = f"{_IDEMPOTENCY_PREFIX}{tenant_id}:{key}"
        resp_body = response.body if hasattr(response, "body") else b""
        await self.redis.setex(
            full_key,
            _IDEMPOTENCY_TTL_MAP.get(tier, 300),
            json.dumps(
                {
                    "status": response.status_code,
                    "body": resp_body.decode() if resp_body else "",
                    "headers": {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower() not in ("set-cookie", "authorization")
                    },
                    "payload_hash": body_hash,
                }
            ),
        )

    def _record_slo(self, request: Request, start_time: float, status_code: int = 200) -> None:
        from sdk.utils import SLO_AVAILABILITY_TOTAL, SLO_LATENCY_SECONDS

        duration = time.time() - start_time
        status = "success" if status_code < 400 else "error"
        SLO_AVAILABILITY_TOTAL.labels(service="gateway", status=status).inc()
        SLO_LATENCY_SECONDS.labels(service="gateway", route=request.url.path).observe(
            duration
        )

    async def _filter_response(self, response: Response) -> Response:
        content_type = response.headers.get("content-type", "")
        if not any(t in content_type for t in ("json", "text", "xml")):
            return response
        try:
            body = b""
            async for chunk in response.body_iterator:
                body += chunk if isinstance(chunk, bytes) else chunk.encode()
            filtered = inference_proxy.filter_output(body)
            return Response(
                content=filtered,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
        except Exception as exc:
            logger.critical("output_redaction_error", error=str(exc))
            return self._deny("Internal Security Error", 500)

    def _process_autonomous_abuse(self, tenant_id: str, client_ip: str, user_agent: str) -> None:
        async def _incr() -> None:
            abuse_key = f"acp:abuse:{tenant_id}"
            ip_key = f"acp:abuse:ips:{tenant_id}"
            ua_key = f"acp:abuse:uas:{tenant_id}"

            count = await self.redis.incr(abuse_key)
            await self.redis.sadd(ip_key, client_ip)
            await self.redis.sadd(ua_key, user_agent)

            if count == 1:
                await self.redis.expire(abuse_key, 300)
                await self.redis.expire(ip_key, 300)
                await self.redis.expire(ua_key, 300)

            unique_ips = await self.redis.scard(ip_key)
            unique_uas = await self.redis.scard(ua_key)

            # Enterprise NAT handling uses UA entropy explicitly
            if count > 50 and (unique_ips > 3 or unique_uas > 3):
                # Cooldown override check to prevent repetitive locks bypassing mitigation logs
                if await self.redis.get(f"acp:tenant_kill_reason:{tenant_id}"):
                    return

                await self.redis.setex(f"acp:tenant_kill:{tenant_id}", 86400, "1")
                await self.redis.setex(f"acp:tenant_kill_reason:{tenant_id}", 86400, "System engaged automatic blocking due to distributed multi-IP anomaly.")
                logger.critical("autonomous_abuse_kill_engaged", tenant_id=tenant_id)
        asyncio.create_task(_safe_bg(_incr()))

    async def _emit_groq_event(
        self,
        event_id: str,
        tenant_id: str,
        agent_id: str,
        tool: str,
        decision: Any,
    ) -> None:
        """Emit a decision event to the Groq intelligence queue (best-effort)."""
        try:
            payload = {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "tool": tool,
                "decision": decision.action.value if hasattr(decision.action, "value") else str(decision.action),
                "risk_score": float(decision.risk),
                "signals": decision.signals,
                "reasons": decision.reasons,
            }
            await self.redis.xadd(
                "acp:groq_queue",
                {"data": json.dumps(payload, default=str)},
                maxlen=10000,
                approximate=True,
            )
        except Exception:
            pass  # Best-effort — never fail the main request

    def _deny(self, message: str, status_code: int) -> JSONResponse:
        ctx = structlog.contextvars.get_contextvars()

        logger.warning("security_rejection", **{
            "severity": "HIGH",
            "message": message,
            "status_code": status_code,
            "trace_id": ctx.get("trace_id", "unknown"),
            "tenant_id": ctx.get("tenant_id", "unknown"),
            "agent_id": ctx.get("agent_id", "unknown"),
            "confidence": 0.99
        })

        if status_code in (401, 403, 429):
            asyncio.create_task(_safe_bg(self.redis.incr("acp:metrics:blocked_requests")))

            t_id = ctx.get("tenant_id")
            c_ip = ctx.get("client_ip", "unknown")
            u_ag = ctx.get("user_agent", "unknown")

            # Metrics bounds implicitly fail-open being spawned as background Tasks without `try-except`.

            if t_id and t_id != "unknown":
                self._process_autonomous_abuse(str(t_id), str(c_ip), str(u_ag))

        return JSONResponse(
            status_code=status_code,
            content={
                "success": False,
                "error": message,
                "meta": {"code": status_code},
            },
        )

    def _escalate(self, message: str) -> JSONResponse:
        """Return 202 Accepted for escalated actions."""
        logger.info("action_escalated", message=message)
        return JSONResponse(
            status_code=202,
            content={
                "success": True,
                "data": {"status": "pending_approval", "message": message},
                "meta": {"code": 202},
            },
        )

    def _log_decision(
        self, tenant_id: str, agent_id: uuid.UUID, tool: str, decision: Decision, request_id: str
    ) -> None:
        """Log a decision to the audit stream."""
        meta = {
            **decision.metadata,
            "risk_score": decision.risk,
            "reasons": decision.reasons,
            "action": decision.action,
        }
        self._log_audit(
            tenant_id,
            agent_id,
            "behavior_firewall_decision",
            tool,
            decision.action,
            "; ".join(decision.reasons),
            request_id,
            meta,
        )
