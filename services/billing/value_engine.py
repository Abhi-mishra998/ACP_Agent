from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Economic Constants
# ---------------------------------------------------------------------------

_SAVINGS_MAP: dict[str, float] = {
    "kill": 500.0,
    "escalate": 100.0,
    "throttle": 200.0,
    "deny": 50.0,
    "monitor": 0.0,
    "allow": 0.0,
}

_THREAT_ACTIONS = {"kill", "escalate", "deny"}
_COST_ACTIONS = {"throttle"}


class BillingValueEngine:
    """
    Production-grade billing engine.

    Guarantees:
    - Idempotent-safe
    - UUID-safe (CRITICAL FIX)
    - Redis failure-safe
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    # -----------------------------------------------------------------------
    # SAFE NORMALIZATION (🔥 CRITICAL)
    # -----------------------------------------------------------------------

    def _tid(self, tenant_id: uuid.UUID | str) -> str:
        return str(tenant_id)

    def _aid(self, agent_id: uuid.UUID | str | None) -> str | None:
        return str(agent_id) if agent_id else None

    def _safe_action(self, action: str | None) -> str:
        return (action or "").lower()

    # -----------------------------------------------------------------------
    # KEY BUILDERS
    # -----------------------------------------------------------------------

    def _daily_key(self, tenant_id: str) -> str:
        return f"acp:billing:tenant:{tenant_id}:{time.strftime('%Y-%m-%d')}"

    def _monthly_key(self, tenant_id: str) -> str:
        return f"acp:billing:tenant:{tenant_id}:month:{time.strftime('%Y-%m')}"

    def _risk_key(self, tenant_id: str) -> str:
        return f"acp:billing:high_risk_agents:{tenant_id}:{time.strftime('%Y-%m-%d')}"

    def _idempotency_key(self, event_id: str) -> str:
        return f"acp:billing:event:{event_id}"

    # -----------------------------------------------------------------------
    # CORE LOGIC
    # -----------------------------------------------------------------------

    def calculate_saved(self, action: str) -> float:
        return _SAVINGS_MAP.get(action.lower(), 0.0)

    async def record_protection_event(
        self,
        tenant_id: uuid.UUID | str,
        action: str,
        agent_id: uuid.UUID | str | None = None,
        predicted_damage: float | None = None,
        event_id: str | None = None,
    ) -> float:

        tenant_id = self._tid(tenant_id)
        agent_id = self._aid(agent_id)
        action = self._safe_action(action)

        saved = predicted_damage if predicted_damage is not None else self.calculate_saved(action)

        if saved == 0.0 and action not in _THREAT_ACTIONS and action not in _COST_ACTIONS:
            return 0.0

        try:
            if event_id:
                if await self.redis.get(self._idempotency_key(event_id)):
                    return 0.0

            daily_key = self._daily_key(tenant_id)
            monthly_key = self._monthly_key(tenant_id)

            pipe = self.redis.pipeline()

            pipe.hincrbyfloat(daily_key, "money_saved", saved)
            pipe.hincrbyfloat(daily_key, "cost_prevented", saved)

            if action in _THREAT_ACTIONS:
                pipe.hincrby(daily_key, "threats_blocked", 1)
                pipe.hincrby(daily_key, "attacks_blocked", 1)

                if agent_id:
                    pipe.sadd(self._risk_key(tenant_id), str(agent_id))

            if action in _COST_ACTIONS:
                pipe.hincrby(daily_key, "cost_spikes_prevented", 1)

            pipe.expire(daily_key, 86400 * 30)

            pipe.hincrbyfloat(monthly_key, "money_saved", saved)

            if action in _THREAT_ACTIONS:
                pipe.hincrby(monthly_key, "threats_blocked", 1)

            pipe.expire(monthly_key, 86400 * 90)

            if event_id:
                pipe.set(self._idempotency_key(event_id), "1", ex=86400)

            results = await pipe.execute()

            logger.info(
                "billing_event_recorded",
                tenant_id=tenant_id,
                action=action,
                saved_usd=saved,
                agent_id=agent_id,
                redis_ops=len(results),
            )

            return saved

        except Exception as e:
            logger.error(
                "billing_write_failed",
                error=str(e),
                tenant_id=tenant_id,
                action=action,
            )
            return 0.0

    async def get_tenant_billing_summary(
        self, tenant_id: uuid.UUID | str
    ) -> dict[str, Any]:

        tenant_id = self._tid(tenant_id)

        try:
            pipe = self.redis.pipeline()
            pipe.hgetall(self._daily_key(tenant_id))
            pipe.hgetall(self._monthly_key(tenant_id))
            pipe.smembers(self._risk_key(tenant_id))

            daily_raw, monthly_raw, risk = await pipe.execute()

            def decode(d: dict | None) -> dict:
                if not d:
                    return {}
                return {
                    (k.decode() if isinstance(k, bytes) else k):
                    (v.decode() if isinstance(v, bytes) else v)
                    for k, v in d.items()
                }

            daily = decode(daily_raw)
            monthly = decode(monthly_raw)

            return {
                "tenant_id": tenant_id,
                "today": {
                    "money_saved": float(daily.get("money_saved", 0)),
                    "threats_blocked": int(daily.get("threats_blocked", 0)),
                    "cost_spikes_prevented": int(daily.get("cost_spikes_prevented", 0)),
                    "high_risk_agents_count": len(risk or []),
                },
                "month": {
                    "money_saved": float(monthly.get("money_saved", 0)),
                    "threats_blocked": int(monthly.get("threats_blocked", 0)),
                },
                "total_money_saved": float(daily.get("money_saved", 0)),
                "attacks_blocked": int(daily.get("attacks_blocked", 0)),
                "cost_prevented": float(daily.get("cost_prevented", 0)),
                "high_risk_agents": [
                    r.decode() if isinstance(r, bytes) else r for r in (risk or [])
                ],
            }

        except Exception as e:
            logger.error(
                "billing_summary_failed",
                error=str(e),
                tenant_id=tenant_id,
            )
            return {
                "tenant_id": tenant_id,
                "today": {},
                "month": {},
                "total_money_saved": 0.0,
                "attacks_blocked": 0,
                "cost_prevented": 0.0,
                "high_risk_agents": [],
            }


def get_value_engine(redis: Redis) -> BillingValueEngine:
    """Factory function to get a BillingValueEngine instance."""
    return BillingValueEngine(redis)
