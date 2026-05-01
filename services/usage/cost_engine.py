import time
from typing import Any

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

# Constants for Cost Protection
WINDOW_ONE_HOUR = 3600
WINDOW_EIGHT_HOURS = 28800
SPIKE_THRESHOLD = 3.0  # 3x baseline triggers risk

class CostEngine:
    """
    Financial Guardrail Engine.
    Detects anomalous financial consumption (token spikes) and protects agent budgets.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis
        self.TENANT_DAILY_LIMIT = 500000.0  # Max budget tokens/day

    def _get_key(self, agent_id: str, window: str) -> str:
        return f"acp:usage:a:{agent_id}:w:{window}"

    def _get_tenant_daily_key(self, tenant_id: str) -> str:
        date_str = time.strftime("%Y-%m-%d")
        return f"acp:cost:tenant:{tenant_id}:{date_str}"

    async def record_usage(self, agent_id: str, tokens: int) -> None:
        """
        Records token usage in multiple time windows for baseline calculation.
        """
        now = int(time.time())
        pipe = self.redis.pipeline()

        # 1. Add to 1h window (for current velocity)
        hour_key = self._get_key(agent_id, "1h")
        pipe.zadd(hour_key, {str(now): now})
        pipe.expire(hour_key, WINDOW_ONE_HOUR)  # M-8 fix: ZSET must also expire
        pipe.incrby(f"{hour_key}:sum", tokens)
        pipe.expire(f"{hour_key}:sum", WINDOW_ONE_HOUR)

        # 2. Add to 8h window (for baseline)
        eight_key = self._get_key(agent_id, "8h")
        pipe.incrby(f"{eight_key}:sum", tokens)
        pipe.expire(f"{eight_key}:sum", WINDOW_EIGHT_HOURS)

        await pipe.execute()

    async def record_tenant_cost_and_check_budget(self, tenant_id: str, agent_id: str, tokens: int) -> bool:
        """
        Record tenant daily cost and return False if budget exceeded.
        """
        if not tokens:
            return True

        tenant_key = self._get_tenant_daily_key(tenant_id)
        pipe = self.redis.pipeline()
        pipe.incrby(tenant_key, tokens)
        pipe.expire(tenant_key, 86400 * 2)

        results = await pipe.execute()
        current = int(results[0])

        if current >= self.TENANT_DAILY_LIMIT:
            logger.critical("economic_hard_limit_exceeded", tenant_id=tenant_id, cost=current)
            await self.redis.setex(f"acp:tenant_kill:{tenant_id}", 86400, 1)
            return False

        return True

    async def get_cost_anomaly_score(self, agent_id: str) -> float:
        """
        Returns a [0.0 - 1.0] risk score based on token consumption volatility.
        """
        hour_sum = int(await self.redis.get(f"{self._get_key(agent_id, '1h')}:sum") or 0)
        eight_sum = int(await self.redis.get(f"{self._get_key(agent_id, '8h')}:sum") or 0)

        # baseline = average tokens per hour over the last 8h
        # Divide by 8, but handle cases where we have < 8h of data
        baseline = max(eight_sum / 8.0, 100) # Min 100 tokens to avoid noise

        if hour_sum > baseline * SPIKE_THRESHOLD:
            # Linear scaling of risk from 3x baseline up to 10x baseline
            ratio = hour_sum / baseline
            risk = min((ratio - SPIKE_THRESHOLD) / 7.0, 1.0)

            logger.warning("cost_spike_detected", agent_id=agent_id, current=hour_sum, baseline=baseline)
            return risk

        return 0.0

    async def get_usage_summary(self, agent_id: str) -> dict[str, Any]:
        """Returns metadata for the Risk Dashboard."""
        hour_sum = int(await self.redis.get(f"{self._get_key(agent_id, '1h')}:sum") or 0)
        return {
            "tokens_last_hour": hour_sum,
            "cost_status": "stable" if hour_sum < 10000 else "high_usage"
        }
