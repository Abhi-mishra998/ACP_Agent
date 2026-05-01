"""
ACP Production Readiness Harness
=================================
Provides a virtualized environment to run ACP services in-process.
Uses ASGITransport to call services directly.
Mocks Redis and SQLAlchemy to avoid infrastructure dependencies.
"""

import uuid
import datetime
from unittest.mock import AsyncMock, MagicMock
import httpx
from jose import jwt

from sdk.common.config import settings
from services.gateway.main import app as gateway_app
from services.identity.main import app as identity_app
from services.registry.main import app as registry_app
from services.policy.main import app as policy_app

# --- Mock Data ---
TEST_TENANT_ID = uuid.uuid4()
TEST_AGENT_ID = uuid.uuid4()
TEST_SECRET = settings.JWT_SECRET_KEY

def create_test_token(agent_id=TEST_AGENT_ID, tenant_id=TEST_TENANT_ID, expired=False):
    from sdk.common.config import settings
    secret = settings.JWT_SECRET_KEY

    # Use timezone-aware UTC so .timestamp() gives the correct Unix epoch value
    # regardless of the host machine's local timezone setting.
    now_utc = datetime.datetime.now(tz=datetime.timezone.utc)
    exp = now_utc + datetime.timedelta(minutes=15 if not expired else -15)
    payload = {
        "sub": str(agent_id),
        "agent_id": str(agent_id),
        "tenant_id": str(tenant_id),
        "role": "ADMIN",
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, secret, algorithm="HS256")


# --- Mock Infrastructure ---

class MockRedis:
    """
    Full-featured in-memory Redis mock.
    Supports all operations used by RateLimiter and SecurityMiddleware.
    """
    def __init__(self):
        self.data: dict = {}
        self._sets: dict = {}
        self._counters: dict = {}

        # Lua script mock: always return 1 (allow) so rate limits don't block tests
        _script_mock = AsyncMock(return_value=1)
        self.register_script = MagicMock(return_value=_script_mock)

        # Core key-value operations
        self.get = AsyncMock(side_effect=lambda k: self.data.get(k))
        self.set = AsyncMock(side_effect=lambda k, v, **kw: self.data.update({k: v}))
        self.setex = AsyncMock(side_effect=lambda k, t, v: self.data.update({k: v}))
        self.setnx = AsyncMock(side_effect=self._setnx)
        self.delete = AsyncMock(side_effect=self._delete)
        self.exists = AsyncMock(side_effect=lambda k: 1 if k in self.data else 0)
        self.incr = AsyncMock(side_effect=self._incr)
        self.expire = AsyncMock(return_value=True)
        self.ttl = AsyncMock(return_value=300)

        # Set operations
        self.sadd = AsyncMock(side_effect=lambda k, v: self._sets.setdefault(k, set()).add(v))
        self.scard = AsyncMock(side_effect=lambda k: len(self._sets.get(k, set())))

        # Stream operations
        self.xadd = AsyncMock(return_value="1234-0")
        self.xack = AsyncMock(return_value=1)

        # Scan (returns empty async iterator by default)
        self.scan_iter = MagicMock(return_value=self._empty_async_iter())

        # Lifecycle
        self.aclose = AsyncMock()
        self.ping = AsyncMock(return_value=True)

        # Context manager support
        self.__aenter__ = AsyncMock(return_value=self)
        self.__aexit__ = AsyncMock()

    def _setnx(self, k, v):
        if k in self.data:
            return 0
        self.data[k] = v
        return 1

    def _delete(self, *keys):
        for k in keys:
            self.data.pop(k, None)

    def _incr(self, k):
        val = int(self.data.get(k, 0)) + 1
        self.data[k] = str(val)
        return val

    @staticmethod
    async def _empty_async_iter():
        # Async generator that yields nothing
        return
        yield  # pragma: no cover


class MockDB:
    def __init__(self):
        self.session = AsyncMock()
        self.session.commit = AsyncMock()
        self.session.rollback = AsyncMock()
        self.session.close = AsyncMock()
        self.session.__aenter__ = AsyncMock(return_value=self.session)
        self.session.__aexit__ = AsyncMock()


# --- The Harness ---

class ProductionAuditHarness:
    def __init__(self):
        self.redis = MockRedis()
        self.db = MockDB()

        # Inject MockRedis into already-created SecurityMiddleware instance
        self._inject_mock_redis()

        # Service Transports (httpx 0.28.1+ style)
        self.gateway = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://gateway.test"
        )
        self.identity = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=identity_app),
            base_url="http://identity.test"
        )
        self.policy = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=policy_app),
            base_url="http://policy.test"
        )
        self.registry = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=registry_app),
            base_url="http://registry.test"
        )

    def _inject_mock_redis(self) -> None:
        """
        Replace the real Redis client in the already-created SecurityMiddleware
        and ServiceClient with our in-memory MockRedis.
        This is necessary because the gateway module initialises Redis at import
        time (module-level `redis = get_redis_client(...)`), before any test
        fixture can patch it.
        """
        import json
        import services.gateway.main as gw_main
        from services.gateway.middleware import SecurityMiddleware
        from services.gateway.client import service_client
        from sdk.common.ratelimit import RateLimiter

        # Replace the module-level redis reference so lifespan callbacks use mock
        gw_main.redis = self.redis

        # Wire into ServiceClient caches
        service_client.set_redis(self.redis)

        # Pre-seed agent metadata for TEST_AGENT_ID so _handle_security_phase
        # doesn't return 403 "Agent not found" before reaching decision evaluation.
        # Permissions include "unknown-tool" (the value _get_tool_name() returns
        # for /v1/tools/execute path) so ToolGuard passes and mocked policy runs.
        agent_cache_key = f"acp:agent:meta:{TEST_AGENT_ID}"
        agent_data = {
            "id": str(TEST_AGENT_ID),
            "name": "test-agent",
            "status": "active",
            "permissions": [
                {"tool_name": "unknown-tool", "action": "allow", "granted_by": str(TEST_TENANT_ID)},
                {"tool_name": "read_file", "action": "allow", "granted_by": str(TEST_TENANT_ID)},
            ]
        }
        self.redis.data[agent_cache_key] = json.dumps(agent_data)

        # Starlette builds the middleware_stack lazily on first request.
        # Before that, the kwargs are stored in app.user_middleware.
        # Replace the 'redis' kwarg in SecurityMiddleware's entry so that when the
        # stack is built on the first test request, it receives MockRedis.
        for mw in gw_main.app.user_middleware:
            if mw.cls is SecurityMiddleware:
                mw.kwargs['redis'] = self.redis
                break

        # If the stack was already built (re-used harness), walk it and patch in-place.
        current = gw_main.app.middleware_stack
        while current is not None:
            if isinstance(current, SecurityMiddleware):
                current.redis = self.redis
                current.limiter = RateLimiter(self.redis)
                break
            current = getattr(current, 'app', None)

    async def stop(self):
        await self.gateway.aclose()
        await self.identity.aclose()
        await self.policy.aclose()
        await self.registry.aclose()

    @staticmethod
    def get_headers(token=None, internal=False, tenant_id=None):
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": str(tenant_id or TEST_TENANT_ID)
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if internal:
            headers["X-Internal-Secret"] = settings.INTERNAL_SECRET
        return headers


# Singleton for reuse
harness = ProductionAuditHarness()
