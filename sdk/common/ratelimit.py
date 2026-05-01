from __future__ import annotations

import time

import structlog
from redis.asyncio import Redis

from sdk.common.config import settings

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# LUA SCRIPT
# Loaded once at class init; sha cached via redis.register_script()
# ---------------------------------------------------------------------------

_LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2]) -- tokens per second
local cost = tonumber(ARGV[3]) or 1
local now = tonumber(ARGV[4]) -- current timestamp in seconds

local bucket_data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket_data[1])
local last_refill = tonumber(bucket_data[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
else
    local time_passed = math.max(0, now - last_refill)
    local refill = time_passed * refill_rate
    tokens = math.min(capacity, tokens + refill)
    last_refill = now
end

local allowed = 0
if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
local expire_time = math.ceil(capacity / refill_rate) * 2
if expire_time < 60 then
    expire_time = 60
end
redis.call('EXPIRE', key, expire_time)

return allowed
"""


class RateLimiter:
    """
    Atomic Redis Lua rate limiter (Token Bucket).
    All public methods return True (allowed) or False (denied).
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        # Register script once
        self._script = redis.register_script(_LUA_TOKEN_BUCKET)

    # ------------------------------------------------------------------
    # PUBLIC API (request-based)
    # ------------------------------------------------------------------

    async def check_limit(
        self, key: str, limit: int, window_seconds: int, tier: str = "basic", check_pool: bool = True
    ) -> bool:
        """
        Token Bucket rate check with Priority-Aware isolation.

        Tiers:
          - enterprise: Reserved capacity. Only checks per-tenant bucket.
          - premium/basic: Fair share. Checks both per-tenant bucket AND global best-effort pool.

        check_pool=False skips the shared pool decrement — pass False for agent/token calls
        when the tenant call on the same request has already decremented it.
        """
        now = time.time()

        # 1. Check Global Best-Effort Pool for non-enterprise tiers
        if tier != "enterprise" and check_pool:
            # Best Effort pool is shared across all non-enterprise tenants
            # We use a 50% system-wide capacity for best effort
            be_key = "acp:ratelimit:best_effort_pool"
            be_limit = int(settings.GLOBAL_RATE_LIMIT * 0.5)
            be_refill_rate = be_limit / 60

            be_allowed = await self._script(
                keys=[be_key],
                args=[be_limit, be_refill_rate, 1, now],
            )
            if not int(be_allowed):
                logger.warning("best_effort_pool_exhausted", tenant_key=key, tier=tier)
                return False

        # 2. Check individual tenant bucket
        capacity = limit
        refill_rate = limit / window_seconds if window_seconds > 0 else limit

        result = await self._script(
            keys=[key],
            args=[capacity, refill_rate, 1, now],
        )
        allowed = int(result) > 0

        if not allowed:
            logger.warning("rate_limit_exceeded", key=key, tier=tier, limit=limit)

        return allowed

    # ------------------------------------------------------------------
    # TOKEN-BASED LIMITING
    # ------------------------------------------------------------------

    async def check_token_limit(
        self,
        jti: str | None,
        agent_id: str,
        limit: int,
        window_seconds: int,
        tier: str = "basic",
        check_pool: bool = True,
    ) -> bool:
        """
        Per-token rate limit. Uses JWT `jti` as the primary key.
        Falls back to agent_id key when jti is absent.
        """
        key = f"rate:token:{jti}" if jti else f"rate:agent:{agent_id}"

        return await self.check_limit(key, limit, window_seconds, tier=tier, check_pool=check_pool)


async def get_rate_limiter(redis: Redis) -> RateLimiter:
    """Return a RateLimiter instance."""
    return RateLimiter(redis)
