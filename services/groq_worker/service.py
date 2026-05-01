"""
Groq Intelligence Worker (standalone variant)
=============================================
Async post-decision LLM enrichment — NOT in the hot request path.
Identical semantics to services.insight.worker; kept as an alternative
deployment target (e.g. a dedicated worker pod).

Consumes acp:groq_queue, writes to:
  acp:groq:insight:{event_id}     (24-hour TTL)
  acp:groq:insights:timeline      (sorted set for recent-first queries)
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from typing import Any

import structlog
from groq import AsyncGroq

from sdk.common.config import settings

logger = structlog.get_logger(__name__)

if not settings.GROQ_API_KEY or "change_me" in settings.GROQ_API_KEY:
    logger.error("GROQ_API_KEY is not configured or is still a placeholder. Groq worker cannot start.")
    sys.exit(1)

GROQ_QUEUE_KEY = "acp:groq_queue"
GROQ_INSIGHT_TTL = 86400          # 24 hours
GROQ_TIMELINE_KEY_PREFIX = "acp:groq:insights:timeline"  # per-tenant: {prefix}:{tenant_id}
GROQ_TIMELINE_MAX = 500
GROQ_CONSUMER_GROUP = "acp:groq_worker"
GROQ_CONSUMER_NAME = "worker-1"

_HIGH_RISK_THRESHOLD = 0.65
_MODEL_DEEP = settings.GROQ_MODEL        # llama-3.3-70b-versatile
_MODEL_FAST = settings.GROQ_MODEL_FAST   # llama-3.1-8b-instant
_GROQ_CONCURRENCY = 5                    # max parallel Groq calls

_SYSTEM_PROMPT = """\
You are an enterprise AI security analyst producing threat intelligence briefings \
for an AI agent governance platform. Analyze blocked or high-risk agent \
tool-execution events and generate concise, actionable security insights.
Return ONLY valid JSON — no markdown, no text outside the JSON object.\
"""

_USER_TEMPLATE = """\
Analyze this AI agent security event and produce threat intelligence.

EVENT:
  Agent ID  : {agent_id}
  Tool      : {tool}
  Decision  : {decision}
  Risk Score: {risk_score:.3f}

SIGNALS (if available):
  {signals_block}

Return exactly this JSON schema:
{{
  "root_cause": "<1-sentence root cause>",
  "threat_classification": "PROMPT_INJECTION|DATA_EXFILTRATION|COST_ABUSE|COORDINATED_ATTACK|ANOMALOUS_BEHAVIOR|POLICY_VIOLATION|BENIGN_ANOMALY",
  "recommendation": "HIGHLIGHT|MONITOR|THROTTLE|ESCALATE|TERMINATE",
  "confidence": "HIGH|MEDIUM|LOW",
  "narrative": "<2-3 sentence executive summary>"
}}\
"""


def _pick_model(risk_score: float) -> str:
    return _MODEL_DEEP if risk_score >= _HIGH_RISK_THRESHOLD else _MODEL_FAST


def _build_signals_block(event: dict) -> str:
    raw = event.get("signals", "")
    if not raw:
        return "not available"
    try:
        signals = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        if isinstance(signals, dict):
            return "  ".join(f"{k}={v:.3f}" for k, v in signals.items() if isinstance(v, (int, float)))
    except Exception:
        pass
    return str(raw)[:200]


class GroqWorker:
    def __init__(self, redis, groq_api_key: str) -> None:
        self.redis = redis
        self._client = AsyncGroq(api_key=groq_api_key)
        self._semaphore = asyncio.Semaphore(_GROQ_CONCURRENCY)

    async def _ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(
                GROQ_QUEUE_KEY, GROQ_CONSUMER_GROUP, id="0", mkstream=True
            )
        except Exception:
            pass  # group already exists

    async def _call_groq(self, event: dict[str, Any]) -> dict[str, Any] | None:
        risk = float(event.get("risk_score", 0.0))
        model = _pick_model(risk)
        user_msg = _USER_TEMPLATE.format(
            agent_id=event.get("agent_id", "unknown"),
            tool=event.get("tool", "unknown"),
            decision=event.get("decision", "unknown"),
            risk_score=risk,
            signals_block=_build_signals_block(event),
        )
        async with self._semaphore:
            return await self._call_groq_inner(model, user_msg, event)

    async def _call_groq_inner(self, model: str, user_msg: str, event: dict[str, Any]) -> dict[str, Any] | None:
        try:
            completion = await self._client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=400,
            )
            result = json.loads(completion.choices[0].message.content)
            result["groq_model"] = model
            result["event_id"] = str(event.get("event_id", ""))
            return result
        except Exception as exc:
            logger.error("groq_call_failed", error=str(exc), event_id=event.get("event_id"))
            return None

    async def _process_batch(self) -> int:
        messages = await self.redis.xreadgroup(
            GROQ_CONSUMER_GROUP,
            GROQ_CONSUMER_NAME,
            {GROQ_QUEUE_KEY: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            return 0

        processed = 0
        for _stream, entries in messages:
            for msg_id, fields in entries:
                try:
                    event = {
                        (k.decode() if isinstance(k, bytes) else k):
                        (v.decode() if isinstance(v, bytes) else v)
                        for k, v in fields.items()
                    }

                    # Unwrap middleware-wrapped payload
                    if "data" in event and isinstance(event["data"], str):
                        try:
                            event = {**event, **json.loads(event["data"])}
                        except Exception:
                            pass

                    try:
                        uuid.UUID(event.get("tenant_id", ""))
                        uuid.UUID(event.get("agent_id", ""))
                    except ValueError:
                        logger.warning("invalid_identity_fields", event_id=event.get("event_id"))
                        await self.redis.xack(GROQ_QUEUE_KEY, GROQ_CONSUMER_GROUP, msg_id)
                        processed += 1
                        continue

                    event_id = event.get("event_id", str(uuid.uuid4()))

                    # Idempotency check
                    cache_key = f"acp:groq:insight:{event_id}"
                    if await self.redis.exists(cache_key):
                        await self.redis.xack(GROQ_QUEUE_KEY, GROQ_CONSUMER_GROUP, msg_id)
                        processed += 1
                        continue

                    insight = await self._call_groq(event)
                    if insight:
                        payload = json.dumps({**insight, "event_id": event_id})
                        await self.redis.setex(cache_key, GROQ_INSIGHT_TTL, payload)

                        # Sorted set for time-ordered /insights queries — per-tenant
                        ts = time.time()
                        tenant_id = event.get("tenant_id", "")
                        timeline_key = f"{GROQ_TIMELINE_KEY_PREFIX}:{tenant_id}" if tenant_id else GROQ_TIMELINE_KEY_PREFIX
                        await self.redis.zadd(timeline_key, {event_id: ts})
                        await self.redis.zremrangebyrank(timeline_key, 0, -(GROQ_TIMELINE_MAX + 1))
                        await self.redis.expire(timeline_key, GROQ_INSIGHT_TTL * 2)

                        # Notify frontend via SSE pub/sub
                        if tenant_id:
                            try:
                                await self.redis.publish(
                                    f"acp:events:{tenant_id}",
                                    json.dumps({
                                        "type": "insight_generated",
                                        "data": {
                                            "event_id": event_id,
                                            "agent_id": event.get("agent_id", ""),
                                            "tool": event.get("tool", ""),
                                            "threat_classification": insight.get("threat_classification"),
                                            "recommendation": insight.get("recommendation"),
                                            "confidence": insight.get("confidence"),
                                            "narrative": (insight.get("narrative") or "")[:300],
                                            "groq_model": insight.get("groq_model"),
                                            "ts": int(ts),
                                        },
                                    }),
                                )
                            except Exception:
                                pass

                        logger.info(
                            "groq_insight_stored",
                            event_id=event_id,
                            model=insight.get("groq_model"),
                            action=insight.get("recommendation"),
                            confidence=insight.get("confidence"),
                        )

                        if insight.get("recommendation") == "ESCALATE":
                            await self.redis.xadd(
                                "acp:alerts",
                                {"event_id": event_id, "narrative": insight.get("narrative", "")},
                            )

                    await self.redis.xack(GROQ_QUEUE_KEY, GROQ_CONSUMER_GROUP, msg_id)
                    processed += 1
                except Exception as exc:
                    logger.error("groq_worker_event_error", msg_id=msg_id, error=str(exc))
        return processed

    async def run(self) -> None:
        await self._ensure_group()
        logger.info("groq_worker_started", queue=GROQ_QUEUE_KEY, model_deep=_MODEL_DEEP, model_fast=_MODEL_FAST)
        while True:
            try:
                count = await self._process_batch()
                if count == 0:
                    await asyncio.sleep(1)
            except Exception as exc:
                logger.error("groq_worker_loop_error", error=str(exc))
                await asyncio.sleep(5)

    async def close(self) -> None:
        await self._client.close()


async def get_recent_insights(redis, tenant_id: str, limit: int = 10) -> list[dict]:
    """Return the most recent N insights from the tenant-scoped sorted set, newest first."""
    results = []
    timeline_key = f"{GROQ_TIMELINE_KEY_PREFIX}:{tenant_id}" if tenant_id else GROQ_TIMELINE_KEY_PREFIX
    event_ids = await redis.zrevrange(timeline_key, 0, limit - 1)
    for raw_id in event_ids:
        event_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
        raw = await redis.get(f"acp:groq:insight:{event_id}")
        if raw:
            try:
                results.append(json.loads(raw))
            except Exception:
                pass
    return results
