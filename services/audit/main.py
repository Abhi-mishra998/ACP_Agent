"""
ACP Audit Service — Stream Consumer + FastAPI App
==================================================
Lifespan:
  1. Create DB tables
  2. Ensure Redis Stream consumer group exists
  3. Start background stream consumer task
  4. On shutdown: cancel consumer task + dispose engine

Stream consumer:
  - Reads from "acp:audit_stream" via XREADGROUP
  - Writes each event to PostgreSQL via AuditWriter
  - ACKs each message on success (ensures at-least-once delivery)
  - Handles pending (unacked) messages on startup
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI
from redis.asyncio import Redis

from sdk.common.audit_hash import GENESIS_HASH, compute_event_hash
from sdk.common.db import engine, get_session_factory
from sdk.common.migrate import check_schema
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.audit.database import SessionLocal, settings
from services.audit.router import router
from services.audit.schemas import AuditLogCreate
from services.audit.writer import AuditWriter

logger = structlog.get_logger(__name__)

_STREAM_KEY = "acp:audit_stream"
_DLQ_KEY = "acp:audit_stream:dlq"
_CONSUMER_GROUP = "acp:audit:consumers"
_CONSUMER_NAME = "audit-service-1"
_BLOCK_MS = 2000  # block 2s waiting for new messages
_BATCH_SIZE = 50  # messages per read cycle
_RETRY_SLEEP = 1.0  # seconds to sleep on error


def _compute_chain_hash(prev_hash: str, event: AuditLogCreate) -> str:
    """Canonical hash: delegates to sdk.common.audit_hash (SINGLE formula)."""
    return compute_event_hash(
        prev_hash=prev_hash,
        tenant_id=str(event.tenant_id),
        agent_id=str(event.agent_id),
        action=event.action,
        tool=event.tool,
        decision=event.decision,
        request_id=event.request_id,
    )

async def _get_prev_hash(redis: Redis, tenant_id: uuid.UUID) -> str:
    """Fetches current chain head from Redis. Returns GENESIS_HASH if first event."""
    key = f"acp:audit:chain:head:{tenant_id}"
    res = await redis.get(key)
    if res:
        return res.decode() if isinstance(res, bytes) else res
    return GENESIS_HASH

async def _update_chain_head(redis: Redis, tenant_id: uuid.UUID, event_hash: str) -> None:
    """Updates chain head in Redis for sequential enforcement."""
    key = f"acp:audit:chain:head:{tenant_id}"
    await redis.set(key, event_hash)

def _parse_stream_event(
    fields: dict[bytes, bytes] | dict[str, str],
) -> AuditLogCreate | None:
    """Convert raw Redis stream fields to AuditLogCreate schema."""
    try:
        # Redis returns bytes when decode_responses=False
        decoded: dict[str, Any] = {
            k.decode() if isinstance(k, bytes) else k: v.decode()
            if isinstance(v, bytes)
            else v
            for k, v in fields.items()
        }

        metadata_raw = decoded.get("metadata_json", "{}")
        try:
            metadata = json.loads(metadata_raw)
        except Exception:
            metadata = {}

        return AuditLogCreate(
            tenant_id=uuid.UUID(decoded["tenant_id"]),
            agent_id=uuid.UUID(decoded["agent_id"]),
            action=decoded.get("action", "unknown"),
            tool=decoded.get("tool"),
            decision=decoded.get("decision", "unknown"),
            reason=decoded.get("reason"),
            request_id=decoded.get("request_id"),
            metadata_json=metadata,
        )
    except Exception as exc:
        logger.error(
            "audit_event_parse_failed", error=str(exc), fields=str(fields)[:200]
        )
        return None


async def _ensure_consumer_group(redis: Redis) -> None:
    """Creates the Redis Stream consumer group if it does not already exist."""
    try:
        await redis.xgroup_create(_STREAM_KEY, _CONSUMER_GROUP, id="0", mkstream=True)
        logger.info("audit_consumer_group_created", group=_CONSUMER_GROUP)
    except Exception as exc:
        if "BUSYGROUP" in str(exc):
            logger.debug("audit_consumer_group_already_exists", group=_CONSUMER_GROUP)
        else:
            logger.error("audit_consumer_group_error", error=str(exc))
            raise


async def _process_pending(redis: Redis) -> None:
    """Process any messages that were delivered but not ACKed (e.g. from a crash)."""
    try:
        pending = await redis.xpending_range(
            _STREAM_KEY, _CONSUMER_GROUP, "-", "+", count=100
        )
        if not pending:
            return

        logger.info("audit_processing_pending", count=len(pending))
        ids = [entry["message_id"] for entry in pending]
        messages = await redis.xclaim(
            _STREAM_KEY,
            _CONSUMER_GROUP,
            _CONSUMER_NAME,
            min_idle_time=0,
            message_ids=ids,
        )
        async with SessionLocal() as db:
            for _, fields in messages:
                event = _parse_stream_event(fields)
                if event:
                    try:
                        # Log is idempotent now with ON CONFLICT
                        await AuditWriter.log(db, redis, event)
                    except Exception as exc:
                        logger.error("audit_pending_write_failed", error=str(exc))
        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, *ids)
    except Exception as exc:
        logger.warning("audit_pending_check_failed", error=str(exc))


async def _check_backpressure(redis: Redis) -> None:
    """Check for consumer lag and stream length, logging warnings if high."""
    try:
        groups = await redis.xinfo_groups(_STREAM_KEY)
        for g in groups:
            if g["name"] == _CONSUMER_GROUP:
                lag = g.get("lag", 0)
                if lag and lag > 1000:
                    logger.warning("audit_consumer_lag_detected", lag=lag)

        # Risk Detection: Check if Stream is near configured MAXLEN (100k)
        stream_len = await redis.xlen(_STREAM_KEY)
        if stream_len > 90_000:
            logger.critical(
                "audit_loss_risk_detected", length=stream_len, threshold=100000
            )
    except Exception as exc:
        logger.warning("backpressure_check_failed", error=str(exc))


async def _stream_consumer_loop(redis: Redis) -> None:
    """
    Enterprise-grade background consumer using Redis Consumer Groups.
    """
    logger.info("audit_worker_started", group=_CONSUMER_GROUP, consumer=_CONSUMER_NAME)

    # Process any unacked messages from previous run (crash recovery)
    await _process_pending(redis)

    while True:
        try:
            # Read next batch from stream via consumer group
            messages = await redis.xreadgroup(
                groupname=_CONSUMER_GROUP,
                consumername=_CONSUMER_NAME,
                streams={_STREAM_KEY: ">"},
                count=_BATCH_SIZE,
                block=_BLOCK_MS
            )

            if not messages:
                continue

            # result = [(stream_key, [(msg_id, fields), ...])]
            for _, batch in messages:
                # PE-8 FIX: Share a single DB session across the full batch so the
                # connection pool is not re-acquired for every individual event.
                async with SessionLocal() as db:
                    to_ack: list[bytes | str] = []
                    for event_id, fields in batch:
                        try:
                            event = _parse_stream_event(fields)
                            if not event:
                                raise ValueError("Parse failed — skipping to DLQ")

                            # Cryptographic chaining (sequential, per-tenant)
                            prev_h = await _get_prev_hash(redis, event.tenant_id)
                            event.prev_hash = prev_h
                            event.event_hash = _compute_chain_hash(prev_h, event)

                            await AuditWriter.log(db, redis, event)

                            # Update chain head in Redis only after successful DB write
                            await _update_chain_head(redis, event.tenant_id, event.event_hash)

                            to_ack.append(event_id)

                        except Exception as exc:
                            logger.error("audit_worker_event_failed", event_id=event_id, error=str(exc))
                            # Dead-letter queue for terminal failures; still ACK to advance
                            await redis.xadd(_DLQ_KEY, {
                                "identity": str(event_id),
                                "payload": json.dumps({
                                    k.decode() if isinstance(k, bytes) else k:
                                    v.decode() if isinstance(v, bytes) else v
                                    for k, v in fields.items()
                                }),
                                "error": str(exc),
                                "ts": str(time.time()),
                            })
                            to_ack.append(event_id)

                    # Batch-acknowledge all processed messages in a single XACK call
                    if to_ack:
                        await redis.xack(_STREAM_KEY, _CONSUMER_GROUP, *to_ack)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("audit_worker_loop_error", error=str(exc))
            await asyncio.sleep(_RETRY_SLEEP)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Create tables, start stream consumer, clean up on shutdown."""
    # 1. Validate DB schema before accepting traffic
    async with get_session_factory()() as db:
        await check_schema(db, "audit")

    # 2. Connect Redis and ensure consumer group
    redis = get_redis_client(settings.REDIS_URL, decode_responses=False)
    await _ensure_consumer_group(redis)

    # 2. Start consumer background task
    consumer_task = asyncio.create_task(_stream_consumer_loop(redis))

    logger.info("audit_service_started")
    yield

    # 3. Graceful shutdown with durability guarantee
    logger.info("audit_service_shutting_down_gracefully")

    # Signal consumer to stop (will catch CancelledError)
    consumer_task.cancel()

    # Wait for consumer to finish processing current batch
    try:
        await asyncio.wait_for(consumer_task, timeout=10.0)
    except TimeoutError:
        logger.warning("audit_consumer_shutdown_timeout")
    except asyncio.CancelledError:
        pass

    # Final cleanup
    await redis.aclose()
    await engine.dispose()
    logger.info("audit_service_stopped")


app = FastAPI(
    title="ACP Audit Service",
    description="Centralized immutable logging for agent actions — Stream consumer",
    version="2.0.0",
    lifespan=lifespan,
)

# Consolidated SDK Setup
setup_app(app, "audit")

app.include_router(router)
