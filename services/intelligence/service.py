"""
Intelligence Service
====================
FIX M-9: get_system_intelligence() stub replaced with real Redis aggregation.
         Returns live coordinated_risk and anomaly_frequency from the ZSET windows.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import structlog
from redis.asyncio import Redis

from sdk.common.config import settings
from sdk.common.redis import get_redis_client

logger = structlog.get_logger(__name__)

# Constants for Cross-Agent Intelligence
SHARED_ANOMALY_TTL = 3600  # 1 hour
MIN_AGENTS_FOR_CORRELATION = 2


class IntelligenceService:
    """
    Analyzes patterns across multiple agents to detect coordinated campaigns.
    Identifies shared anomalies and unusual tool clusters.
    """

    def __init__(self, redis: Redis | None = None) -> None:
        self.redis = redis or get_redis_client(settings.REDIS_URL)

    def _get_key(self, tenant_id: uuid.UUID | None, suffix: str) -> str:
        tid = str(tenant_id) if tenant_id else "global"
        return f"acp:intelligence:t:{tid}:{suffix}"

    async def report_anomaly(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, sequence: list[str], flags: list[str]
    ) -> float:
        """
        Record an anomaly and check for correlations with other agents.
        Uses Time-Windowed Pattern Hashing for hyperscale detection.
        """
        if not sequence and not flags:
            return 0.0

        now = time.time()
        window_start = now - 300  # 5 minute rolling window

        pattern_str = ",".join(sequence)
        pattern_hash = hashlib.sha256(pattern_str.encode()).hexdigest()

        signal_str = ":".join(sorted(flags))
        signal_hash = hashlib.sha256(signal_str.encode()).hexdigest()

        try:
            pipe = self.redis.pipeline()

            pk = self._get_key(tenant_id, f"zpattern:{pattern_hash}")
            pipe.zadd(pk, {str(agent_id): now})
            pipe.zremrangebyscore(pk, 0, window_start)
            pipe.expire(pk, 600)

            sk = self._get_key(tenant_id, f"zsignal:{signal_hash}")
            pipe.zadd(sk, {str(agent_id): now})
            pipe.zremrangebyscore(sk, 0, window_start)
            pipe.expire(sk, 600)

            await pipe.execute()

            p_agents = await self.redis.zcard(pk)
            s_agents = await self.redis.zcard(sk)

            p_risk = min(0.9, (p_agents - 1) * 0.3) if p_agents >= 2 else 0.0
            s_risk = min(0.6, (s_agents - 1) * 0.15) if s_agents >= 2 else 0.0

            final_risk = max(p_risk, s_risk)

            if final_risk > 0.5:
                logger.warning(
                    "windowed_correlation_anomaly_detected",
                    agent_id=str(agent_id),
                    agents_involved=max(p_agents, s_agents),
                    pattern=pattern_hash[:8],
                    risk=final_risk,
                )

            return final_risk
        except Exception as exc:
            logger.error("intelligence_correlation_error", error=str(exc))
            return 0.0

    async def get_system_intelligence(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        """
        M-9 FIX: Real aggregation from Redis pattern/signal ZSET windows.

        Returns:
            coordinated_risk: max risk score across all active pattern windows for this tenant.
            anomaly_frequency: total number of unique agent observations reported in last 5 min.
        """
        try:
            pattern_prefix = self._get_key(tenant_id, "zpattern:")
            signal_prefix = self._get_key(tenant_id, "zsignal:")

            # Scan for all active pattern and signal keys for this tenant
            pattern_keys = []
            signal_keys = []
            async for key in self.redis.scan_iter(f"{pattern_prefix}*"):
                pattern_keys.append(key)
            async for key in self.redis.scan_iter(f"{signal_prefix}*"):
                signal_keys.append(key)

            coordinated_risk = 0.0
            anomaly_frequency = 0

            # Aggregate across all active pattern windows
            for key in pattern_keys:
                count = await self.redis.zcard(key)
                if count >= MIN_AGENTS_FOR_CORRELATION:
                    risk = min(0.9, (count - 1) * 0.3)
                    coordinated_risk = max(coordinated_risk, risk)
                anomaly_frequency += count

            for key in signal_keys:
                count = await self.redis.zcard(key)
                if count >= MIN_AGENTS_FOR_CORRELATION:
                    risk = min(0.6, (count - 1) * 0.15)
                    coordinated_risk = max(coordinated_risk, risk)

            return {
                "coordinated_risk": round(coordinated_risk, 4),
                "anomaly_frequency": anomaly_frequency,
                "active_pattern_windows": len(pattern_keys),
                "active_signal_windows": len(signal_keys),
            }
        except Exception as exc:
            logger.error("get_system_intelligence_error", error=str(exc))
            return {
                "coordinated_risk": 0.0,
                "anomaly_frequency": 0,
                "active_pattern_windows": 0,
                "active_signal_windows": 0,
            }


# Global singleton
intelligence_engine = IntelligenceService()
