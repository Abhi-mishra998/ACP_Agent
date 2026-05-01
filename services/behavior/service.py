"""
Behavioral Intelligence Layer
==============================
Phase 2 upgrade: 4 production-grade detection capabilities.

1. SEQUENCE TRACKING  — detect patterns like read→read→read→delete
2. VELOCITY DETECTION — abnormal request spikes (ZSET sliding window)
3. COST EXPLOSION     — token usage anomalies (integrates CostEngine)
4. CROSS-AGENT CORRELATION — coordinated campaign detection

All risk scores output are normalised to [0.0, 1.0].
The old 0–100 modifier scale has been eliminated.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from redis.asyncio import Redis

from sdk.common.config import settings
from sdk.common.invariants import clamp_risk
from sdk.common.redis import get_redis_client
from services.behavior.schemas import BehaviorAnalysis
from services.intelligence.service import intelligence_engine
from services.learning.service import learning_engine

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Tuneable constants (all in one place)
# ---------------------------------------------------------------------------

HISTORY_WINDOW_SIZE = 50          # actions kept in sliding list
VELOCITY_WINDOW_SECONDS = 60      # 1-minute RPM window
VELOCITY_THRESHOLD_RPM = 100      # requests/min → velocity_risk starts rising
VELOCITY_MAX_RPM = 500            # RPM where velocity_risk reaches 1.0
LOOP_DETECT_LENGTH = 3            # N identical consecutive tools = loop
SEQUENCE_N_GRAM = 3               # n-gram length for sequence fingerprinting

# Dangerous action sequences — O(1) lookup
_DANGEROUS_SEQUENCES: set[tuple[str, ...]] = {
    ("read", "read", "delete"),
    ("read", "read", "read", "delete"),
    ("list", "list", "drop_table"),
    ("query", "query", "exfiltrate"),
    ("scan", "scan", "exfiltrate"),
    ("read", "write", "delete"),
}


class BehaviorService:
    """
    Real-time Behavioral Intelligence Layer for AI agent monitoring.
    Produces structured BehaviorAnalysis with 4 risk dimensions.
    """

    def __init__(self, redis_client: Redis | None = None) -> None:
        self.redis = redis_client or get_redis_client(settings.REDIS_URL)
        # C-7 FIX: instantiate once, not per-request
        from services.usage.cost_engine import CostEngine
        self._cost_engine = CostEngine(self.redis)

    def set_redis(self, redis: Redis) -> None:
        """Inject shared Redis client (called by gateway lifespan)."""
        self.redis = redis

    def _key(self, tenant_id: uuid.UUID, agent_id: uuid.UUID, suffix: str) -> str:
        return f"acp:behavior:t:{tenant_id}:a:{agent_id}:{suffix}"

    # ------------------------------------------------------------------
    # 1. SEQUENCE TRACKING
    # ------------------------------------------------------------------

    async def _compute_sequence_risk(
        self, history: list[str], tool: str
    ) -> tuple[float, list[str]]:
        """
        Detect dangerous n-gram sequences and simple loops.
        Returns (sequence_risk [0.0-1.0], flags).
        """
        flags: list[str] = []
        risk = 0.0

        # Simple loop detection: N identical consecutive tools
        if len(history) >= LOOP_DETECT_LENGTH and all(
            t == history[0] for t in history[:LOOP_DETECT_LENGTH]
        ):
            risk = max(risk, 0.70)
            flags.append(f"tool_loop_detected:{history[0]}")

        # Immediate repetition (mild)
        if len(history) >= 2 and history[0] == history[1]:
            risk = max(risk, 0.30)
            flags.append("repeated_tool_call")

        # Dangerous sequence n-gram matching
        window = [tool] + list(history[:SEQUENCE_N_GRAM - 1])
        normalized = tuple(t.lower().split("_")[0] for t in reversed(window))
        if normalized in _DANGEROUS_SEQUENCES:
            risk = max(risk, 0.85)
            flags.append(f"dangerous_sequence:{'>'.join(normalized)}")

        # Check longer windows too
        if len(history) >= 3:
            window4 = [tool] + list(history[:3])
            norm4 = tuple(t.lower().split("_")[0] for t in reversed(window4))
            if norm4 in _DANGEROUS_SEQUENCES:
                risk = max(risk, 0.85)
                flags.append(f"dangerous_sequence:{'>'.join(norm4)}")

        return clamp_risk(risk), flags

    # ------------------------------------------------------------------
    # 2. VELOCITY DETECTION
    # ------------------------------------------------------------------

    async def _compute_velocity_risk(
        self, velocity_key: str, now: float
    ) -> tuple[float, float, list[str]]:
        """
        Returns (velocity_risk [0.0-1.0], rpm: float, flags).
        Uses ZSET sliding window for O(log N) accuracy.
        """
        pipe = self.redis.pipeline()
        pipe.zadd(velocity_key, {str(now): now})
        pipe.zremrangebyscore(velocity_key, 0, now - VELOCITY_WINDOW_SECONDS)
        pipe.expire(velocity_key, VELOCITY_WINDOW_SECONDS * 2)
        pipe.zcard(velocity_key)
        results = await pipe.execute()
        rpm = float(results[3])

        flags: list[str] = []
        if rpm > VELOCITY_THRESHOLD_RPM:
            risk = clamp_risk(
                (rpm - VELOCITY_THRESHOLD_RPM) / (VELOCITY_MAX_RPM - VELOCITY_THRESHOLD_RPM)
            )
            flags.append(f"velocity_spike:{rpm:.0f}rpm")
            return risk, rpm, flags

        return 0.0, rpm, flags

    # ------------------------------------------------------------------
    # 3. COST EXPLOSION DETECTION (via CostEngine integration)
    # ------------------------------------------------------------------

    async def _compute_cost_risk(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, tokens: int
    ) -> tuple[float, list[str]]:
        """
        Returns (cost_risk [0.0-1.0], flags).
        Delegates to usage/cost_engine for ZSET-based spike detection.
        """
        flags: list[str] = []
        try:
            if tokens > 0:
                await self._cost_engine.record_usage(str(agent_id), tokens)
            cost_risk = await self._cost_engine.get_cost_anomaly_score(str(agent_id))
            if cost_risk > 0.3:
                flags.append(f"cost_spike:{cost_risk:.2f}")
            return clamp_risk(cost_risk), flags
        except Exception as exc:
            logger.warning("cost_engine_unavailable", error=str(exc))
            return 0.0, []

    # ------------------------------------------------------------------
    # PUBLIC: check_behavior (lightweight, for inference proxy read-path)
    # ------------------------------------------------------------------

    async def check_behavior(
        self, agent_id: uuid.UUID, tool_name: str, payload_hash: str, payload_text: str = "", tenant_id: uuid.UUID | None = None
    ) -> Any:
        """
        Read-only behavior check (no state mutation).
        Returns normalised risk modifier [0.0–1.0] instead of 0–100 scale.
        """
        from sdk.common.exceptions import ACPError
        class SecurityException(ACPError):
            def __init__(self, message: str):
                super().__init__(message=message, status_code=403)

        # Defense-in-depth: Global Blockade
        if tenant_id and await self.redis.get(f"acp:tenant_kill:{tenant_id}"):
            raise SecurityException("Tenant globally blocked")

        # Phase 4: Semantic Input Sanitization Firewall
        if payload_text:
            import re
            norm_payload = payload_text.lower()
            norm_payload = re.sub(r'[^a-z0-9 ]', '', norm_payload)

            risk = 0.0
            if re.search(r"(delete|drop|remove|erase|clear|reset)", norm_payload):
                risk += 0.4

            if re.search(r"(database|data|table|memory|system|state)", norm_payload):
                risk += 0.4

            if re.search(r"(ignore|bypass|override).*(instruction|rule|guardrail|filter)", norm_payload):
                risk += 0.4

            # Context dampening
            if re.search(r"(read|analyze|view|describe|summarize)", norm_payload):
                risk -= 0.2

            if risk >= 0.6:
                raise SecurityException("High-risk destructive intent detected")
        history_key = (
            self._key(tenant_id, agent_id, "history") if tenant_id
            else f"acp:behavior:a:{agent_id}:history"
        )
        history = [t.decode() for t in await self.redis.lrange(history_key, 0, 5)]

        risk, flags = await self._compute_sequence_risk(history, tool_name)

        return type("BehaviorRes", (), {
            "risk_score": risk,           # [0.0–1.0] — NOT 0–100
            "risk_score_modifier": risk,  # kept for backward compat
            "flags": flags,
            "history": history,
        })

    # ------------------------------------------------------------------
    # PUBLIC: record_action (full write path — called by middleware)
    # ------------------------------------------------------------------

    async def record_action(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        tool: str,
        tokens: int = 0,
    ) -> BehaviorAnalysis:
        """
        Record a new action and produce a full 4-dimension BehaviorAnalysis.

        Dimensions:
          behavior_risk    — loop / sequence risk
          anomaly_score    — drift from baseline (learning engine)
          cross_agent_risk — coordinated campaign correlation
          cost_risk        — token consumption spike
        """
        now = time.time()
        history_key = self._key(tenant_id, agent_id, "history")
        velocity_key = self._key(tenant_id, agent_id, "velocity")
        usage_key = self._key(tenant_id, agent_id, "usage")

        # Persist action to history
        pipe = self.redis.pipeline()
        pipe.lpush(history_key, tool)
        pipe.ltrim(history_key, 0, HISTORY_WINDOW_SIZE - 1)
        pipe.expire(history_key, 86400)
        if tokens > 0:
            pipe.hincrby(usage_key, "tokens_used", tokens)
            pipe.hincrby(usage_key, "request_count", 1)
            pipe.expire(usage_key, 86400)
        await pipe.execute()

        # Fetch history for analysis
        history = [t.decode() for t in await self.redis.lrange(history_key, 0, -1)]
        prev_tool = history[1] if len(history) > 1 else None

        # --- Dimension 1: Sequence / Loop Risk ---
        sequence_risk, seq_flags = await self._compute_sequence_risk(history, tool)

        # --- Dimension 2: Velocity Risk ---
        velocity_risk, rpm, vel_flags = await self._compute_velocity_risk(velocity_key, now)

        # --- Dimension 3: Cost Explosion Risk ---
        cost_risk, cost_flags = await self._compute_cost_risk(tenant_id, agent_id, tokens)

        # --- Dimension 4: Learning Engine (drift / anomaly) ---
        try:
            learning_res = await learning_engine.observe_action(
                tenant_id, agent_id, tool, prev_tool, rpm
            )
            anomaly_score = clamp_risk(learning_res.anomaly_score)
            drift_score = clamp_risk(learning_res.drift_score)
            learn_flags = learning_res.reasons
        except Exception as exc:
            logger.error("learning_engine_failed", error=str(exc), agent_id=str(agent_id))
            from services.learning.schemas import LearningResult
            learning_res = LearningResult(
                agent_id=agent_id, tenant_id=tenant_id,
                anomaly_score=0.0, drift_score=0.0,
                confidence=0.0, reasons=["intelligence_degraded"]
            )
            anomaly_score = drift_score = 0.0
            learn_flags = ["intelligence_degraded"]

        # --- Cross-Agent Correlation ---
        cross_agent_risk = 0.0
        if anomaly_score > 0.3:
            try:
                cross_agent_risk = await intelligence_engine.report_anomaly(
                    tenant_id, agent_id, history[:5], learn_flags
                )
            except Exception as exc:
                logger.warning("cross_agent_correlation_failed", error=str(exc))

        # --- Merge: composite behavior risk ---
        # The primary behavior signal is the max of sequence + velocity
        behavior_risk = clamp_risk(max(sequence_risk, velocity_risk))

        all_flags = list(set(seq_flags + vel_flags + cost_flags + learn_flags))

        logger.info(
            "behavior_analysis",
            agent_id=str(agent_id),
            tool=tool,
            behavior_risk=behavior_risk,
            anomaly_score=anomaly_score,
            cost_risk=cost_risk,
            cross_agent_risk=cross_agent_risk,
            velocity_rpm=rpm,
        )

        return BehaviorAnalysis(
            agent_id=agent_id,
            tenant_id=tenant_id,
            behavior_risk=behavior_risk,
            anomaly_score=anomaly_score,
            drift_score=drift_score,
            cross_agent_risk=cross_agent_risk,
            confidence=learning_res.confidence,
            flags=all_flags,
            sequence=history[:10],
            velocity=rpm,
            metadata={
                "sequence_risk": sequence_risk,
                "velocity_risk": velocity_risk,
                "cost_risk": cost_risk,
                "tokens": tokens,
            },
        )

    async def get_usage_metrics(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> dict[str, int]:
        """Fetch real-time usage metrics for the agent."""
        usage_key = self._key(tenant_id, agent_id, "usage")
        metrics = await self.redis.hgetall(usage_key)
        return {k.decode(): int(v) for k, v in metrics.items()}


# Global singleton
behavior_engine = BehaviorService()
