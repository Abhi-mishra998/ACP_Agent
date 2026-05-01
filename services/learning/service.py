from __future__ import annotations

import asyncio
import math
import uuid
from typing import Any

import structlog
from redis.asyncio import Redis

from sdk.common.config import settings
from sdk.common.redis import get_redis_client
from services.learning.database import async_session
from services.learning.repository import LearningRepository
from services.learning.schemas import LearningResult, ProbabilisticProfile

logger = structlog.get_logger(__name__)

# Constants for Learning Engine
ANOMALY_THRESHOLD = 0.01  # P < 1% is rare
DRIFT_THRESHOLD = 0.4
MIN_OBSERVATIONS_FOR_BASELINE = 100
DEFAULT_SMOOTHING = 0.1  # Laplace smoothing factor


class LearningService:
    """
    Adaptive behavior firewall engine.
    Upgrades rule-based detection to probabilistic modeling and drift analysis.
    """

    def __init__(self, redis: Redis | None = None) -> None:
        self.redis = redis or get_redis_client(
            settings.REDIS_URL, socket_timeout=2.0, socket_connect_timeout=1.0
        )

    def _get_key(self, tenant_id: uuid.UUID, agent_id: uuid.UUID, suffix: str) -> str:
        return f"acp:learning:t:{str(tenant_id)}:a:{str(agent_id)}:{suffix}"

    async def get_profile(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> ProbabilisticProfile:
        """Fetch historical behavior profile from Redis Hashes."""
        key = self._get_key(tenant_id, agent_id, "profile")

        try:
            raw_data = await self.redis.hgetall(key)
            if not raw_data:
                return ProbabilisticProfile(agent_id=agent_id)

            # Reconstruct profile from flat hash
            data: dict[str, Any] = {
                "agent_id": agent_id,
                "tool_usage_distribution": {},
                "transition_matrix": {},
                "avg_velocity": 0.0,
                "avg_tokens": 0.0,
                "baseline_risk": 0.0,
                "version": 1
            }

            for field_b, value_b in raw_data.items():
                field = field_b.decode() if isinstance(field_b, bytes) else field_b
                value = value_b.decode() if isinstance(value_b, bytes) else value_b

                if field.startswith("dist:"):
                    tool_name = field[5:]
                    data["tool_usage_distribution"][tool_name] = int(value)
                elif field.startswith("trans:"):
                    parts = field[6:].split(":")
                    if len(parts) == 2:
                        tool_a, tool_b = parts
                        if tool_a not in data["transition_matrix"]:
                            data["transition_matrix"][tool_a] = {}
                        data["transition_matrix"][tool_a][tool_b] = int(value)
                elif field in ["avg_velocity", "avg_tokens", "baseline_risk"]:
                    data[field] = float(value)
                elif field == "version":
                    data[field] = int(value)
                elif field == "sum_velocity":
                    data["sum_velocity"] = float(value)
                elif field == "sum_tokens":
                    data["sum_tokens"] = float(value)
                elif field == "total_events":
                    data["total_events"] = int(value)

            # Compute actual averages from sums if present
            total_events = data.get("total_events", 0)
            if total_events > 0:
                if "sum_velocity" in data:
                    data["avg_velocity"] = data["sum_velocity"] / total_events
                if "sum_tokens" in data:
                    data["avg_tokens"] = data["sum_tokens"] / total_events

            return ProbabilisticProfile(**data)
        except Exception as e:
            logger.error("profile_load_failed", error=str(e), key=key)
            # Fail-secure: return a baseline but log error
            return ProbabilisticProfile(agent_id=agent_id)

    async def observe_action(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        tool: str,
        prev_tool: str | None = None,
        velocity: float = 0.0,
        tokens: int = 0
    ) -> LearningResult:
        """
        Atomic update of behavior profile using Redis Hashes.
        """
        key = self._get_key(tenant_id, agent_id, "profile")

        try:
            # 1. Prepare Atomic Batch Updates
            pipe = self.redis.pipeline()

            # Increment version
            pipe.hincrby(key, "version", 1)

            # Update Distribution
            pipe.hincrby(key, f"dist:{tool}", 1)

            # Update Transition Matrix
            if prev_tool:
                pipe.hincrby(key, f"trans:{prev_tool}:{tool}", 1)

            # Update Velocity & Tokens (Exponential Moving Average approximation via HSET)
            # Since we can't easily do EMA in HINCRBYFLOAT without reading,
            # we'll use a conservative update for now or HINCRBYFLOAT for sums.
            # Best Production Practice: Store sums and counts, compute average on read.
            pipe.hincrbyfloat(key, "sum_velocity", velocity)
            pipe.hincrbyfloat(key, "sum_tokens", float(tokens))
            pipe.hincrby(key, "total_events", 1)

            # Execute Pipeline
            results = await pipe.execute()
            if not results:
                raise RuntimeError("Redis pipeline execution failed")

            # 2. Read-After-Write Verification & Refresh
            # We fetch the latest state to perform probabilistic analysis
            profile = await self.get_profile(tenant_id, agent_id)

            # Compute ad-hoc averages for analysis
            # In a distributed system, we want the analysis to be on the most current global state
            total_events = sum(profile.tool_usage_distribution.values())

            # 3. Analysis logic (re-uses current state)
            res = self._calculate_scores(
                tenant_id, profile, tool, prev_tool, velocity, tokens
            )

            # 4. Persistence (Background DB sync)
            if total_events % 10 == 0:
                asyncio.create_task(self._sync_to_db_with_retry(tenant_id, agent_id, profile))

            return res

        except Exception as e:
            logger.critical("observe_action_failed", error=str(e), agent_id=str(agent_id))
            # Fallback: Raise so we don't proceed with inconsistent state
            raise

    def _calculate_scores(
        self,
        tenant_id: uuid.UUID,
        profile: ProbabilisticProfile,
        current_tool: str,
        prev_tool: str | None,
        current_velocity: float,
        current_tokens: int = 0,
        count_before: int = 0,
        total_transitions_before: int = 0
    ) -> LearningResult:
        """
        Perform probabilistic and drift analysis.
        """
        reasons = []
        anomaly_score = 0.0
        drift_score = 0.0

        total_observations = sum(profile.tool_usage_distribution.values())
        confidence = min(total_observations / MIN_OBSERVATIONS_FOR_BASELINE, 1.0)

        # A. Transition Probability (P(next|prev))
        if prev_tool:
            # If we've seen this context (prev_tool) before but NEVER this transition
            if total_transitions_before >= 5 and count_before == 0:
                anomaly_score = 0.6
                reasons.append(f"Unseen transition sequence: {prev_tool} -> {current_tool}")
            elif total_transitions_before > 10:
                probability = (count_before + DEFAULT_SMOOTHING) / (
                    total_transitions_before + DEFAULT_SMOOTHING * 10
                )
                if probability < ANOMALY_THRESHOLD:
                    anomaly_score = min(1.0, -0.2 * math.log(probability))
                    reasons.append(
                        f"Rare tool transition: P({current_tool}|{prev_tool}) = "
                        f"{probability:.4f}"
                    )

        # B. Behavioral Drift (Simple Total Variation approximation)
        total_dist = sum(profile.tool_usage_distribution.values())
        if total_dist > 10:
            count = profile.tool_usage_distribution.get(current_tool, 0)
            # If this tool is new and we have a baseline, it's a drift signal
            if count == 1:
                drift_score += 0.4
                reasons.append(f"Behavioral shift: First use of '{current_tool}' detected.")

        # C. Velocity Anomaly
        if profile.avg_velocity > 0 and current_velocity > profile.avg_velocity * 3:
            anomaly_score = max(anomaly_score, 0.4)
            reasons.append(
                f"Execution velocity spike: {current_velocity:.1f} "
                f"vs baseline {profile.avg_velocity:.1f}"
            )

        # D. Cost Intelligence (Token Spike)
        if profile.avg_tokens > 100 and current_tokens > profile.avg_tokens * 3:
            anomaly_score = max(anomaly_score, 0.5)
            reasons.append(
                f"Economic anomaly: {current_tokens} tokens "
                f"vs baseline {profile.avg_tokens:.1f}"
            )

        return LearningResult(
            agent_id=profile.agent_id,
            tenant_id=tenant_id,
            anomaly_score=round(anomaly_score, 3),
            drift_score=round(drift_score, 3),
            confidence=round(confidence, 3),
            reasons=reasons,
            metadata={
                "observations": total_observations,
                "avg_velocity": round(profile.avg_velocity, 2),
                "avg_tokens": round(profile.avg_tokens, 2)
            }
        )

    async def _sync_to_db_with_retry(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, profile: ProbabilisticProfile, retries: int = 3
    ) -> None:
        """Asynchronously sync profile to DB with exponential backoff retry."""
        # Ensure Redis key doesn't leak forever
        key = self._get_key(tenant_id, agent_id, "profile")
        await self.redis.expire(key, 86400) # 24h TTL on hot data

        for attempt in range(retries):
            try:
                async with async_session() as session:
                    repo = LearningRepository(session)
                    existing = await repo.get_profile(agent_id)

                    payload = {
                        "tool_usage_distribution": profile.tool_usage_distribution,
                        "transition_matrix": profile.transition_matrix,
                        "avg_velocity": profile.avg_velocity,
                        "avg_tokens": profile.avg_tokens,
                        "baseline_risk": profile.baseline_risk,
                        "version": profile.version
                    }

                    if existing:
                        # Version check (Optimistic Locking)
                        if existing.version > profile.version:
                            logger.warning("stale_profile_sync_skipped", agent_id=str(agent_id))
                            return
                        await repo.update_profile(agent_id, **payload)
                    else:
                        await repo.create_profile(agent_id, tenant_id, **payload)

                    logger.info("profile_synced_to_db", agent_id=str(agent_id), version=profile.version)
                    return # Success
            except Exception as e:
                wait = 2 ** attempt
                logger.error("profile_sync_failed", agent_id=str(agent_id), error=str(e), attempt=attempt+1, next_retry=wait)
                await asyncio.sleep(wait)

        logger.critical("profile_sync_permanently_failed", agent_id=str(agent_id))


    async def apply_feedback(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        outcome: str,
        correction: str | None = None
    ) -> None:
        """
        Adjust behavioral baseline based on human feedback (Closed-Loop).
        Stores atomic counters for adaptive weighting: acp:feedback:{agent_id}
        """
        profile_key = self._get_key(tenant_id, agent_id, "profile")
        feedback_key = f"acp:feedback:{str(agent_id)}"

        try:
            pipe = self.redis.pipeline()

            # 1. Update Profile (Version + Baseline)
            if correction == "false_positive":
                pipe.hset(profile_key, "baseline_risk", 0.0)
                pipe.hincrby(profile_key, "version", 1)

            # 2. Update Adaptive Counters
            pipe.hincrby(feedback_key, "total_decisions", 1)
            if correction == "false_positive":
                pipe.hincrby(feedback_key, "false_positives", 1)
            elif correction == "true_positive":
                pipe.hincrby(feedback_key, "true_positives", 1)

            # Set TTL on feedback stats (e.g., 30 days) to prevent memory leak
            pipe.expire(feedback_key, 2592000)

            await pipe.execute()
            logger.info("learning_engine_feedback_recorded", agent_id=str(agent_id), correction=correction)

            # Fetch updated profile and sync to DB to ensure durability of feedback
            profile = await self.get_profile(tenant_id, agent_id)
            await self._sync_to_db_with_retry(tenant_id, agent_id, profile)
        except Exception as e:
            logger.error("apply_feedback_failed", error=str(e), agent_id=str(agent_id))
# Global instance
learning_engine = LearningService()
