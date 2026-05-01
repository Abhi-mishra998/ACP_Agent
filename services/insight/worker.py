"""
Insight Worker
==============
Async post-decision LLM enrichment — NOT in the hot request path.
Consumes acp:groq_queue Redis stream, calls Groq API, stores enriched
insights in:
  acp:groq:insight:{event_id}     (hash, 24-hour TTL)
  acp:groq:insights:timeline      (sorted set, score=unix_ts, for /insights?limit=N)
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid

import structlog
from groq import AsyncGroq
from pydantic import BaseModel, Field
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sdk.common.config import settings
from sdk.common.redis import get_redis_client

logging.basicConfig(level=logging.INFO)
logger = structlog.get_logger(__name__)

if not settings.GROQ_API_KEY or "change_me" in settings.GROQ_API_KEY:
    logger.error("GROQ_API_KEY is not configured or is still a placeholder. Insight worker cannot start.")
    sys.exit(1)

redis = get_redis_client(settings.REDIS_URL, decode_responses=False)
groq_client = AsyncGroq(api_key=settings.GROQ_API_KEY)

_STREAM_KEY = "acp:groq_queue"
_DLQ_KEY = "acp:groq:dlq"
_CONSUMER_GROUP = "acp:insight:consumers"
_CONSUMER_NAME = "insight-worker-primary"
_TIMELINE_KEY = "acp:groq:insights:timeline"
_INSIGHT_TTL = 86400          # 24 hours — security insights need to outlast the shift
_TIMELINE_MAX = 500           # keep at most 500 entries in the sorted set

# Route high-risk events to the larger, more capable model
_HIGH_RISK_THRESHOLD = 0.65
_MODEL_DEEP = settings.GROQ_MODEL        # llama-3.3-70b-versatile (best quality)
_MODEL_FAST = settings.GROQ_MODEL_FAST   # llama-3.1-8b-instant  (low-risk events)

_SYSTEM_PROMPT = """\
You are an enterprise AI security analyst producing threat intelligence briefings \
for an AI agent governance platform. You analyze blocked or high-risk agent \
tool-execution events and generate concise, actionable security insights for \
executive review.

Return ONLY valid JSON — no markdown, no explanation text outside the JSON object.\
"""

_USER_TEMPLATE = """\
Analyze the following AI agent security event and produce threat intelligence.

EVENT DETAILS:
  Agent ID  : {agent_id}
  Tool      : {tool}
  Decision  : {decision}  (enforced by the security engine)
  Risk Score: {risk_score:.3f}

SIGNALS (if available):
  {signals_block}

Return exactly this JSON schema:
{{
  "root_cause": "<1-sentence root cause analysis>",
  "threat_classification": "PROMPT_INJECTION|DATA_EXFILTRATION|COST_ABUSE|COORDINATED_ATTACK|ANOMALOUS_BEHAVIOR|POLICY_VIOLATION|BENIGN_ANOMALY",
  "recommendation": "HIGHLIGHT|MONITOR|THROTTLE|ESCALATE|TERMINATE",
  "confidence": "HIGH|MEDIUM|LOW",
  "narrative": "<2-3 sentence executive summary of the threat and recommended response>"
}}\
"""


class InsightResponse(BaseModel):
    root_cause: str
    threat_classification: str = Field(
        description="OWASP-aligned or generic threat classification"
    )
    recommendation: str = Field(
        description="Must be one of: HIGHLIGHT, MONITOR, THROTTLE, ESCALATE, TERMINATE"
    )
    confidence: str = Field(description="Must be one of: HIGH, MEDIUM, LOW")
    narrative: str = Field(description="2-3 sentence executive summary")


def _pick_model(risk_score: float) -> str:
    return _MODEL_DEEP if risk_score >= _HIGH_RISK_THRESHOLD else _MODEL_FAST


def _build_signals_block(event: dict) -> str:
    """Format signal data from the event into a readable block for the prompt."""
    signals_raw = event.get("signals", "")
    if not signals_raw:
        return "not available"
    try:
        signals = json.loads(signals_raw) if isinstance(signals_raw, (str, bytes)) else signals_raw
        if not isinstance(signals, dict):
            return str(signals_raw)
        return "  ".join(f"{k}={v:.3f}" for k, v in signals.items() if isinstance(v, (int, float)))
    except Exception:
        return str(signals_raw)[:200]


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=15),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(Exception),
    reraise=True,
)
async def generate_insight(event: dict) -> dict:
    risk_score = float(event.get("risk_score", 0.0))
    model = _pick_model(risk_score)

    user_msg = _USER_TEMPLATE.format(
        agent_id=event.get("agent_id", "unknown"),
        tool=event.get("tool", "unknown"),
        decision=event.get("decision", "unknown"),
        risk_score=risk_score,
        signals_block=_build_signals_block(event),
    )

    completion = await groq_client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=400,
    )

    raw = completion.choices[0].message.content
    data = json.loads(raw)
    validated = InsightResponse(**data)
    result = validated.model_dump()
    result["groq_model"] = model
    return result


async def ensure_consumer_group() -> None:
    try:
        await redis.xgroup_create(_STREAM_KEY, _CONSUMER_GROUP, id="0", mkstream=True)
        logger.info("consumer_group_ready", group=_CONSUMER_GROUP)
    except Exception as e:
        if "BUSYGROUP" not in str(e):
            logger.error("consumer_group_init_failed", error=str(e))
            sys.exit(1)


async def store_insight(event_id: str, insight: dict) -> None:
    """Persist insight and add to the time-ordered sorted set for recent queries."""
    cache_key = f"acp:groq:insight:{event_id}"
    payload = json.dumps({**insight, "event_id": event_id})
    await redis.setex(cache_key, _INSIGHT_TTL, payload)

    # Maintain a sorted set so GET /insights returns genuinely recent items
    ts = time.time()
    await redis.zadd(_TIMELINE_KEY, {event_id: ts})
    # Trim to keep only the latest _TIMELINE_MAX entries
    await redis.zremrangebyrank(_TIMELINE_KEY, 0, -(_TIMELINE_MAX + 1))

    logger.info(
        "insight_stored",
        event_id=event_id,
        model=insight.get("groq_model"),
        classification=insight.get("threat_classification"),
        confidence=insight.get("confidence"),
    )


async def process_groq_queue() -> None:
    await ensure_consumer_group()
    logger.info("insight_worker_started", queue=_STREAM_KEY)

    while True:
        try:
            messages = await redis.xreadgroup(
                _CONSUMER_GROUP, _CONSUMER_NAME, {_STREAM_KEY: ">"}, count=10, block=2000
            )

            for _, msgs in messages:
                for msg_id, fields in msgs:
                    event = {
                        (k.decode() if isinstance(k, bytes) else k):
                        (v.decode() if isinstance(v, bytes) else v)
                        for k, v in fields.items()
                    }

                    # Events from middleware wrap payload under a "data" key
                    if "data" in event and isinstance(event["data"], str):
                        try:
                            event = {**event, **json.loads(event["data"])}
                        except Exception:
                            pass

                    event_id = event.get("event_id") or str(uuid.uuid4())

                    # Validate tenant/agent UUIDs to reject malformed entries
                    try:
                        uuid.UUID(event.get("tenant_id", ""))
                        uuid.UUID(event.get("agent_id", ""))
                    except ValueError:
                        logger.warning("invalid_identity_fields", event_id=event_id)
                        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, msg_id)
                        continue

                    # Idempotency — skip if already processed
                    cache_key = f"acp:groq:insight:{event_id}"
                    if await redis.exists(cache_key):
                        logger.info("insight_skipped_idempotent", event_id=event_id)
                        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, msg_id)
                        continue

                    try:
                        insight = await generate_insight(event)
                        await store_insight(event_id, insight)

                        # Notify frontend via SSE pub/sub
                        tenant_id = event.get("tenant_id", "")
                        if tenant_id:
                            try:
                                await redis.publish(
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
                                            "ts": int(time.time()),
                                        },
                                    }),
                                )
                            except Exception:
                                pass

                        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, msg_id)
                    except Exception as err:
                        logger.error("insight_generation_failed", event_id=event_id, error=str(err))
                        await redis.xadd(
                            _DLQ_KEY,
                            {"event_data": json.dumps(event), "error": str(err)},
                            maxlen=1000,
                        )
                        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, msg_id)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("worker_loop_error", error=str(e))
            await asyncio.sleep(2)


if __name__ == "__main__":
    try:
        asyncio.run(process_groq_queue())
    except KeyboardInterrupt:
        logger.info("insight_worker_shutting_down")
