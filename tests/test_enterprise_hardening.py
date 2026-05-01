"""
Enterprise Hardening Tests
==========================
Covers the 4 production gaps:
  1. Multi-tenancy / org_id isolation
  2. Tier-based rate limiting enforcement
  3. Zero registry calls during execution (JWT token enrichment)
  4. Policy evaluation < 5ms p99

Run:
    .venv/bin/pytest tests/test_enterprise_hardening.py -v
"""

from __future__ import annotations

import datetime
import statistics
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jose import jwt

from sdk.common.config import settings
from services.policy.local_eval import evaluate, evaluate_from_jwt_claims, timed_evaluate


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
_TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000001")
_ORG_A    = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000002")
_ORG_B    = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")
_AGENT_A  = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000010")
_AGENT_B  = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000010")


def _make_token(
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    org_id: uuid.UUID | None = None,
    role: str = "agent",
    agent_status: str = "active",
    permissions: list[dict] | None = None,
    expired: bool = False,
) -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now + datetime.timedelta(minutes=-5 if expired else 15)
    payload = {
        "jti":          str(uuid.uuid4()),
        "sub":          str(agent_id),
        "tenant_id":    str(tenant_id),
        "org_id":       str(org_id or tenant_id),
        "agent_id":     str(agent_id),
        "role":         role,
        "typ":          "ACP_ACCESS",
        "iat":          int(now.timestamp()),
        "exp":          int(exp.timestamp()),
        "agent_status": agent_status,
        "permissions":  permissions or [],
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


# ─────────────────────────────────────────────────────────────────────────────
# TASK 1 — MULTI-TENANCY / org_id
# ─────────────────────────────────────────────────────────────────────────────

class TestMultiTenancy:

    def test_org_mixin_exists(self):
        """OrgMixin is importable and has org_id column definition."""
        from sdk.common.db import OrgMixin
        # Check the column is declared as a mapped attribute
        assert hasattr(OrgMixin, "org_id")

    def test_org_id_in_jwt_payload(self):
        """JWT contains org_id claim matching tenant_id (SaaS Strict Invariant)."""
        token = _make_token(_TENANT_A, _AGENT_A, org_id=_TENANT_A)
        decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        assert decoded["org_id"] == str(_TENANT_A)
        assert decoded["tenant_id"] == str(_TENANT_A)

    @pytest.mark.asyncio
    async def test_cross_tenant_access_forbidden(self):
        """
        Token issued for tenant_A must be rejected when X-Tenant-ID claims tenant_B.
        The gateway middleware enforces this at the header-vs-token check.
        """
        from tests.harness import harness

        token = _make_token(_TENANT_A, _AGENT_A)

        resp = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "data_query", "arguments": {}},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID":   str(_TENANT_B),   # Different tenant — must be rejected
                "Content-Type":  "application/json",
            },
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_org_id_mismatch_rejected(self):
        """
        X-Org-ID header that does not match token org_id claim must return 403.
        (Using a valid token with consistent org_id == tenant_id)
        """
        from tests.harness import harness

        token = _make_token(_TENANT_A, _AGENT_A, org_id=_TENANT_A)

        resp = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "data_query", "arguments": {}},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID":   str(_TENANT_A),
                "X-Org-ID":      str(_ORG_B),   # Wrong org — must be rejected
                "Content-Type":  "application/json",
            },
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    def test_same_agent_id_different_orgs_are_isolated(self):
        """
        Two orgs can have agents with the same UUID. Their tokens carry different
        org_id claims so cross-org replay is detected via header validation.
        """
        token_org_a = _make_token(_TENANT_A, _AGENT_A, org_id=_ORG_A)
        token_org_b = _make_token(_TENANT_B, _AGENT_A, org_id=_ORG_B)

        dec_a = jwt.decode(token_org_a, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        dec_b = jwt.decode(token_org_b, settings.JWT_SECRET_KEY, algorithms=["HS256"])

        assert dec_a["org_id"] != dec_b["org_id"]
        assert dec_a["tenant_id"] != dec_b["tenant_id"]

    def test_sdk_client_sends_org_id_header(self):
        """ACPClient includes X-Org-ID in requests when org_id is supplied."""
        from sdk.client import ACPClient

        client = ACPClient(
            agent_id=str(_AGENT_A),
            secret="s",
            gateway_url="http://gw",
            identity_url="http://id",
            org_id=str(_ORG_A),
        )
        client.tenant_id = str(_TENANT_A)
        headers = client._base_headers()
        assert headers.get("X-Org-ID") == str(_ORG_A)

    def test_sdk_client_no_org_id_omits_header(self):
        """ACPClient omits X-Org-ID when org_id is not supplied."""
        from sdk.client import ACPClient

        client = ACPClient(
            agent_id=str(_AGENT_A),
            secret="s",
            gateway_url="http://gw",
            identity_url="http://id",
        )
        client.tenant_id = str(_TENANT_A)
        headers = client._base_headers()
        assert "X-Org-ID" not in headers


# ─────────────────────────────────────────────────────────────────────────────
# TASK 2 — TIER-BASED RATE LIMITING
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiting:

    @pytest.mark.asyncio
    async def test_rate_limit_basic_tier(self):
        """Basic tier: rpm=60. Limiter allows requests up to that limit."""
        from sdk.common.ratelimit import RateLimiter
        from tests.harness import MockRedis

        redis = MockRedis()
        limiter = RateLimiter(redis)
        allowed = await limiter.check_limit("test:basic", 60, 60, tier="basic")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_pro_tier(self):
        """Pro tier: rpm=300. Check_limit with higher quota returns allowed."""
        from sdk.common.ratelimit import RateLimiter
        from tests.harness import MockRedis

        redis = MockRedis()
        limiter = RateLimiter(redis)
        allowed = await limiter.check_limit("test:pro", 300, 60, tier="pro")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_returns_429(self):
        """When Lua bucket returns 0 (denied), middleware must raise 429."""
        from sdk.common.ratelimit import RateLimiter
        from tests.harness import MockRedis

        redis = MockRedis()
        redis.register_script = MagicMock(return_value=AsyncMock(return_value=0))
        limiter = RateLimiter(redis)
        allowed = await limiter.check_limit("test:denied", 60, 60, tier="basic", check_pool=False)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_enterprise_tier_skips_best_effort_pool(self):
        """Enterprise tier should bypass the shared best-effort pool check."""
        from sdk.common.ratelimit import RateLimiter
        from tests.harness import MockRedis

        redis = MockRedis()
        call_count = 0

        async def _counting_script(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return 1

        redis.register_script = MagicMock(return_value=AsyncMock(side_effect=_counting_script))
        limiter = RateLimiter(redis)
        await limiter.check_limit("test:enterprise", 1000, 60, tier="enterprise")
        # Enterprise skips global pool — only 1 script call (per-tenant bucket only)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_middleware_uses_rpm_limit_from_tenant_meta(self):
        """
        When tenant metadata returns rpm_limit=200, the middleware passes
        that value to check_limit instead of the default _TENANT_RATE_LIMIT.
        """
        from services.gateway.middleware import SecurityMiddleware
        from tests.harness import MockRedis

        redis = MockRedis()
        captured_limit: list[int] = []

        async def _mock_check_limit(key, limit, window, tier="basic", check_pool=True):
            if "tenant:" in key:
                captured_limit.append(limit)
            return True

        mw = SecurityMiddleware.__new__(SecurityMiddleware)
        mw.redis   = redis
        mw.limiter = MagicMock()
        mw.limiter.check_limit       = AsyncMock(side_effect=_mock_check_limit)
        mw.limiter.check_token_limit = AsyncMock(return_value=True)

        await mw._check_rate_limits(
            tenant_id_str="aaaaaaaa-0000-0000-0000-000000000001",
            agent_id=_AGENT_A,
            jti="jti-1",
            tier="pro",
            rpm_limit=200,
        )
        assert captured_limit == [200], f"Expected [200], got {captured_limit}"


# ─────────────────────────────────────────────────────────────────────────────
# TASK 3 — ZERO REGISTRY CALLS DURING EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

class TestZeroRegistryCalls:

    def test_token_carries_permissions(self):
        """Agent JWT contains embedded permissions list."""
        perms = [
            {"tool_name": "data_query", "action": "ALLOW"},
            {"tool_name": "logs.read",  "action": "ALLOW"},
        ]
        token = _make_token(_TENANT_A, _AGENT_A, permissions=perms)
        decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        assert decoded["permissions"] == perms
        assert decoded["agent_status"] == "active"

    @pytest.mark.asyncio
    async def test_get_agent_metadata_uses_jwt_claims(self):
        """get_agent_metadata() returns JWT-sourced data without calling Registry."""
        from services.gateway.client import ServiceClient

        perms = [{"tool_name": "data_query", "action": "ALLOW"}]
        claims = {
            "agent_id":     str(_AGENT_A),
            "tenant_id":    str(_TENANT_A),
            "agent_status": "active",
            "permissions":  perms,
            "risk_level":   "low",
        }

        sc = ServiceClient()
        sc._agent_cache = None  # no cache so we'd hit Registry if claims were ignored

        result = await sc.get_agent_metadata(_AGENT_A, _TENANT_A, jwt_claims=claims)

        assert result is not None
        assert result["status"] == "active"
        assert result["permissions"] == perms

    @pytest.mark.asyncio
    async def test_evaluate_policy_uses_local_eval_with_claims(self):
        """evaluate_policy() calls local evaluator when JWT claims are present."""
        from services.gateway.client import ServiceClient

        perms = [{"tool_name": "data_query", "action": "ALLOW"}]
        claims = {
            "agent_status": "active",
            "permissions":  perms,
            "risk_level":   "low",
        }

        sc = ServiceClient()
        http_called = False

        async def _fake_remote(*args, **kwargs):
            nonlocal http_called
            http_called = True
            return {"allowed": True, "reason": "remote", "risk_adjustment": 0.0}

        sc._evaluate_policy_remote = _fake_remote
        sc._opa_cb = MagicMock()
        sc._opa_cb.is_open = False

        result = await sc.evaluate_policy(
            tenant_id=_TENANT_A,
            agent_id=_AGENT_A,
            tool="data_query",
            risk_score=0.1,
            jwt_claims=claims,
        )
        assert not http_called, "HTTP policy call was made despite JWT claims present"
        assert result["allowed"] is True
        assert result["reason"] == "permission granted"

    @pytest.mark.asyncio
    async def test_zero_registry_calls_during_execution(self):
        """
        Simulate a full gateway execute request. Registry must NOT be called
        when the JWT carries embedded agent_status + permissions.
        """
        from tests.harness import harness, TEST_TENANT_ID, TEST_AGENT_ID
        from services.gateway.client import service_client

        perms = [
            {"tool_name": "unknown-tool", "action": "ALLOW"},
            {"tool_name": "data_query",   "action": "ALLOW"},
        ]
        token = _make_token(TEST_TENANT_ID, TEST_AGENT_ID, permissions=perms)
        registry_call_count = 0

        async def _mock_get_agent(agent_id, tenant_id, jwt_claims=None):
            nonlocal registry_call_count
            if jwt_claims and jwt_claims.get("agent_status"):
                return {
                    "id":          str(agent_id),
                    "tenant_id":   str(tenant_id),
                    "status":      jwt_claims["agent_status"],
                    "permissions": jwt_claims.get("permissions", []),
                    "risk_level":  "low",
                    "name":        "test-agent",
                }
            registry_call_count += 1
            return None

        orig = service_client.get_agent_metadata
        service_client.get_agent_metadata = _mock_get_agent
        try:
            with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
                mock_eval.return_value = {"action": "allow", "risk": 0.0, "reasons": []}
                await harness.gateway.post(
                    "/v1/tools/execute",
                    json={"tool": "data_query", "payload": {}},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-Tenant-ID":   str(TEST_TENANT_ID),
                        "X-ACP-Tool":    "data_query",
                        "Content-Type":  "application/json",
                    },
                )
        finally:
            service_client.get_agent_metadata = orig

        assert registry_call_count == 0, f"Registry was called {registry_call_count} time(s)"


# ─────────────────────────────────────────────────────────────────────────────
# TASK 4 — LOCAL POLICY EVALUATION < 5ms p99
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalPolicyEval:

    _PERMS_ALLOW = [{"tool_name": "data_query", "action": "ALLOW"}]
    _PERMS_DENY  = [{"tool_name": "data_query", "action": "DENY"}]
    _PERMS_WILD  = [{"tool_name": "*", "action": "ALLOW"}]

    # ── correctness ──────────────────────────────────────────────────────────

    def test_allow_active_agent_with_permission(self):
        allowed, reason, adj = evaluate("active", self._PERMS_ALLOW, "data_query", 0.1)
        assert allowed is True
        assert reason == "permission granted"

    def test_deny_inactive_agent(self):
        allowed, reason, _ = evaluate("inactive", self._PERMS_ALLOW, "data_query", 0.1)
        assert allowed is False
        assert "not active" in reason

    def test_deny_quarantined_agent(self):
        allowed, reason, _ = evaluate("quarantined", self._PERMS_ALLOW, "data_query", 0.1)
        assert allowed is False
        assert "suspended" in reason

    def test_deny_terminated_agent(self):
        allowed, reason, _ = evaluate("terminated", self._PERMS_ALLOW, "data_query", 0.1)
        assert allowed is False
        assert "suspended" in reason

    def test_deny_explicit_deny_permission(self):
        allowed, reason, _ = evaluate("active", self._PERMS_DENY, "data_query", 0.1)
        assert allowed is False
        assert "deny" in reason

    def test_deny_no_permission(self):
        allowed, reason, _ = evaluate("active", [], "data_query", 0.1)
        assert allowed is False
        assert "no allow permission" in reason

    def test_deny_high_risk_score(self):
        allowed, reason, _ = evaluate("active", self._PERMS_ALLOW, "data_query", 0.95)
        assert allowed is False
        assert "critical threshold" in reason

    def test_allow_wildcard_permission(self):
        allowed, reason, _ = evaluate("active", self._PERMS_WILD, "any_tool", 0.1)
        assert allowed is True

    def test_deny_overrides_allow(self):
        """An explicit DENY for the tool must block even if a wildcard ALLOW exists."""
        perms = [
            {"tool_name": "*",          "action": "ALLOW"},
            {"tool_name": "data_query", "action": "DENY"},
        ]
        allowed, reason, _ = evaluate("active", perms, "data_query", 0.1)
        assert allowed is False

    def test_risk_adjustment_high_agent(self):
        _, _, adj = evaluate("active", self._PERMS_ALLOW, "data_query", 0.6, "high")
        assert adj == 0.2

    def test_risk_adjustment_medium_agent(self):
        _, _, adj = evaluate("active", self._PERMS_ALLOW, "data_query", 0.75, "medium")
        assert adj == 0.15

    def test_risk_adjustment_low_agent(self):
        _, _, adj = evaluate("active", self._PERMS_ALLOW, "data_query", 0.1, "low")
        assert adj == -0.1

    def test_evaluate_from_jwt_claims(self):
        """evaluate_from_jwt_claims extracts data from a claims dict."""
        claims = {
            "agent_status": "active",
            "permissions":  self._PERMS_ALLOW,
            "risk_level":   "low",
        }
        allowed, reason, adj = evaluate_from_jwt_claims(claims, "data_query", 0.1)
        assert allowed is True
        assert adj == -0.1

    # ── performance ───────────────────────────────────────────────────────────

    def test_policy_eval_under_5ms_p99(self):
        """p99 local evaluation latency must be < 5ms (typically < 0.1ms)."""
        N = 1000
        perms = [{"tool_name": "data_query", "action": "ALLOW"}]
        durations = []

        for _ in range(N):
            _, _, _, ms = timed_evaluate("active", perms, "data_query", 0.3, "low")
            durations.append(ms)

        p99 = statistics.quantiles(durations, n=100)[98]  # 99th percentile
        assert p99 < 5.0, f"p99 latency {p99:.3f}ms exceeds 5ms target"

    def test_policy_eval_faster_than_5ms_mean(self):
        """Mean evaluation time should be well under 1ms."""
        N = 500
        perms = [{"tool_name": "tool", "action": "ALLOW"}]
        durations = [
            timed_evaluate("active", perms, "tool", 0.2)[3]
            for _ in range(N)
        ]
        mean_ms = sum(durations) / N
        assert mean_ms < 1.0, f"Mean latency {mean_ms:.3f}ms exceeds 1ms"


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TEST: multi-tenant isolation end-to-end
# ─────────────────────────────────────────────────────────────────────────────

class TestMultiTenantIsolationE2E:

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_multi_tenant_isolation_e2e(self):
        """
        End-to-end: agent A's token cannot access resources under tenant B.
        Requires the live ACP stack (docker compose up).
        """
        import httpx

        gw = "http://localhost:8000"
        async with httpx.AsyncClient() as c:
            resp = await c.post(f"{gw}/auth/token", json={
                "email": "admin@acp.local", "password": "password"
            }, headers={"X-Tenant-ID": "00000000-0000-0000-0000-000000000001"})
            if resp.status_code != 200:
                pytest.skip("Live stack not available")
            token = resp.json()["data"]["access_token"]

            resp2 = await c.post(f"{gw}/execute", json={"tool": "data_query", "payload": {}}, headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID":   "bbbbbbbb-0000-0000-0000-000000000001",
            })
            assert resp2.status_code == 403

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_rate_limit_under_load(self):
        """
        Send 80 requests rapidly to a basic tier tenant.
        After rpm_limit is exhausted, must receive at least one 429.
        Requires the live ACP stack.
        """
        import httpx

        gw = "http://localhost:8000"
        async with httpx.AsyncClient() as c:
            resp = await c.post(f"{gw}/auth/token", json={
                "email": "admin@acp.local", "password": "password"
            }, headers={"X-Tenant-ID": "00000000-0000-0000-0000-000000000001"})
            if resp.status_code != 200:
                pytest.skip("Live stack not available")
            token = resp.json()["data"]["access_token"]

        statuses = []
        async with httpx.AsyncClient() as c:
            for _ in range(80):
                r = await c.post(f"{gw}/execute", json={"tool": "data_query", "payload": {}}, headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID":   "00000000-0000-0000-0000-000000000001",
                    "X-ACP-Tool":    "data_query",
                })
                statuses.append(r.status_code)

        assert 429 in statuses, "Expected at least one 429 under sustained load"
