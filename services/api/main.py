from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from sdk.common.config import settings
from sdk.common.db import engine, get_session_factory
from sdk.common.migrate import check_schema
from sdk.common.redis import get_redis_client
from sdk.utils import setup_app
from services.api.are_worker import process_incident
from services.api.repository.incident import IncidentRepository
from services.api.router.api_key import router as api_key_router
from services.api.router.auto_response import router as are_router
from services.api.router.incident import router as incident_router
from services.api.schemas.incident import IncidentCreate

logger = structlog.get_logger(__name__)

_INCIDENT_STREAM   = "acp:incidents:queue"
_INCIDENT_GROUP    = "api-incident-worker"
_INCIDENT_CONSUMER = "api-worker-1"

_ARE_GROUP    = "are-workers"
_ARE_CONSUMER = "are-worker-1"

_AUDIT_STREAM   = "acp:audit:events"
_AUDIT_ARE_GROUP    = "are-audit-workers"
_AUDIT_ARE_CONSUMER = "are-audit-worker-1"

# Backpressure threshold — pause ARE when backlog exceeds this
_BACKPRESSURE_THRESHOLD = 10_000


async def _incident_consumer(redis, session_factory) -> None:
    """
    Fix 1: Durable Redis Stream consumer for incident creation.
    At-least-once delivery with dedup + retry. Replaces fire-and-forget HTTP.
    """
    # Create consumer group if it doesn't exist
    try:
        await redis.xgroup_create(_INCIDENT_STREAM, _INCIDENT_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    # On startup, re-process any pending (unacknowledged) messages from a prior crash
    await _drain_pending(redis, session_factory)

    while True:
        try:
            msgs = await redis.xreadgroup(
                _INCIDENT_GROUP,
                _INCIDENT_CONSUMER,
                {_INCIDENT_STREAM: ">"},
                count=10,
                block=2000,  # must be < socket_timeout(5s) to avoid spurious TimeoutError
            )
            for _stream, entries in (msgs or []):
                for msg_id, fields in entries:
                    await _process_one(redis, session_factory, msg_id, fields)
        except asyncio.CancelledError:
            break
        except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError) as exc:
            logger.warning("incident_consumer_redis_unavailable", error=str(exc))
            await asyncio.sleep(1)
        except Exception as exc:
            logger.error("incident_consumer_error", error=str(exc))
            await asyncio.sleep(2)


async def _drain_pending(redis, session_factory) -> None:
    """Re-process messages that were fetched but never acknowledged (crash recovery)."""
    try:
        pending = await redis.xpending_range(
            _INCIDENT_STREAM, _INCIDENT_GROUP, "-", "+", count=100
        )
        if not pending:
            return
        ids = [p["message_id"] for p in pending]
        msgs = await redis.xrange(_INCIDENT_STREAM, min=ids[0], max=ids[-1])
        for msg_id, fields in msgs:
            if any(str(p["message_id"]) == str(msg_id) for p in pending):
                await _process_one(redis, session_factory, msg_id, fields)
    except Exception as exc:
        logger.warning("incident_drain_pending_failed", error=str(exc))


async def _process_one(redis, session_factory, msg_id, fields: dict) -> None:
    """Process one stream message: dedup → create/bump → ack."""
    try:
        raw   = fields.get(b"data") or fields.get("data") or b"{}"
        data  = json.loads(raw if isinstance(raw, str) else raw.decode())

        # Fix 2: Deduplication — same agent + tool + trigger within 5-minute window
        time_bucket = int(time.time() // 300)
        dedup_raw   = f"{data.get('tenant_id')}:{data.get('agent_id')}:{data.get('tool', '')}:{data.get('trigger')}:{time_bucket}"
        dedup_hash  = hashlib.sha256(dedup_raw.encode()).hexdigest()[:16]
        dedup_key   = f"acp:incident:dedup:{dedup_hash}"

        existing_id_bytes = await redis.get(dedup_key)

        async with session_factory()() as db:
            repo = IncidentRepository(db)

            if existing_id_bytes:
                # Duplicate — bump violation counter on the existing open incident
                existing_id = existing_id_bytes.decode() if isinstance(existing_id_bytes, bytes) else existing_id_bytes
                try:
                    await repo.bump_violation(uuid.UUID(existing_id))
                    logger.info("incident_dedup_bump", dedup_hash=dedup_hash, incident_id=existing_id)
                except Exception as exc:
                    logger.warning("incident_dedup_bump_failed", error=str(exc))
            else:
                # New incident
                try:
                    payload  = IncidentCreate(**data)
                    incident = await repo.create(payload, dedup_key=dedup_hash)
                    # Set dedup key with 5-min TTL so duplicates in the same window are caught
                    await redis.setex(dedup_key, 300, str(incident.id))
                    logger.info("incident_created_from_queue",
                        number=incident.incident_number,
                        severity=incident.severity,
                        agent_id=incident.agent_id,
                    )
                except Exception as exc:
                    logger.error("incident_create_failed", error=str(exc), data=data)
                    # Don't ack — let it be retried
                    return

        # Acknowledge only on success
        await redis.xack(_INCIDENT_STREAM, _INCIDENT_GROUP, msg_id)

    except Exception as exc:
        logger.error("incident_event_processing_failed", error=str(exc), msg_id=str(msg_id))
        # Don't ack — Redis will redeliver after PEL timeout


# ─── ARE consumer (separate group — evaluates every incident for auto-mitigation) ──

async def _are_consumer(redis, session_factory) -> None:
    """ARE evaluation worker — uses its own consumer group on the incidents stream."""
    try:
        await redis.xgroup_create(_INCIDENT_STREAM, _ARE_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # group already exists

    while True:
        try:
            # Backpressure: pause if queue is too deep
            try:
                backlog = int(await redis.xlen(_INCIDENT_STREAM) or 0)
                if backlog > _BACKPRESSURE_THRESHOLD:
                    logger.warning("are_backpressure", backlog=backlog)
                    await asyncio.sleep(5)
                    continue
            except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError):
                await asyncio.sleep(1)
                continue

            msgs = await redis.xreadgroup(
                _ARE_GROUP, _ARE_CONSUMER,
                {_INCIDENT_STREAM: ">"},
                count=10, block=2000,  # must be < socket_timeout(5s)
            )
            for _stream, entries in (msgs or []):
                for msg_id, fields in entries:
                    await _are_process_one(redis, session_factory, msg_id, fields)
        except asyncio.CancelledError:
            break
        except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError) as exc:
            logger.warning("are_consumer_redis_unavailable", error=str(exc))
            await asyncio.sleep(1)
        except Exception as exc:
            logger.error("are_consumer_error", error=str(exc))
            await asyncio.sleep(2)


async def _are_process_one(redis, session_factory, msg_id, fields: dict) -> None:
    try:
        raw  = fields.get(b"data") or fields.get("data") or b"{}"
        data = json.loads(raw if isinstance(raw, str) else raw.decode())
        await process_incident(redis, session_factory, data)
        await redis.xack(_INCIDENT_STREAM, _ARE_GROUP, msg_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("are_process_failed", error=str(exc), msg_id=str(msg_id))


async def _audit_are_consumer(redis, session_factory) -> None:
    """
    Second ARE ingestion source: consume deny/high-risk events from the audit stream.
    Runs alongside the incidents stream consumer — same process_incident(), different source.
    """
    try:
        await redis.xgroup_create(_AUDIT_STREAM, _AUDIT_ARE_GROUP, id="$", mkstream=True)
    except Exception:
        pass  # group already exists

    while True:
        try:
            try:
                backlog = int(await redis.xlen(_AUDIT_STREAM) or 0)
                if backlog > _BACKPRESSURE_THRESHOLD:
                    await asyncio.sleep(5)
                    continue
            except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError):
                await asyncio.sleep(1)
                continue

            msgs = await redis.xreadgroup(
                _AUDIT_ARE_GROUP, _AUDIT_ARE_CONSUMER,
                {_AUDIT_STREAM: ">"},
                count=10, block=2000,  # must be < socket_timeout(5s)
            )
            for _stream, entries in (msgs or []):
                for msg_id, fields in entries:
                    try:
                        raw  = fields.get(b"data") or fields.get("data") or b"{}"
                        data = json.loads(raw if isinstance(raw, str) else raw.decode())
                        await process_incident(redis, session_factory, data)
                        await redis.xack(_AUDIT_STREAM, _AUDIT_ARE_GROUP, msg_id)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.error("audit_are_process_failed", error=str(exc))
        except asyncio.CancelledError:
            break
        except (redis.exceptions.TimeoutError, redis.exceptions.ConnectionError) as exc:
            logger.warning("audit_are_consumer_redis_unavailable", error=str(exc))
            await asyncio.sleep(1)
        except Exception as exc:
            logger.error("audit_are_consumer_error", error=str(exc))
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # Schema migration check
    async with get_session_factory()() as db:
        await check_schema(db, "api")

    # Redis for stream consumers and action effects
    redis = get_redis_client(settings.REDIS_URL, decode_responses=False)
    _app.state.incident_redis = redis

    # Start durable incident consumer
    consumer_task = asyncio.create_task(
        _incident_consumer(redis, get_session_factory)
    )
    # Start ARE evaluation worker (separate consumer group on incidents stream)
    are_task = asyncio.create_task(
        _are_consumer(redis, get_session_factory)
    )
    # Start ARE audit-events consumer (event-driven: audit deny/high-risk → ARE)
    audit_are_task = asyncio.create_task(
        _audit_are_consumer(redis, get_session_factory)
    )

    yield

    consumer_task.cancel()
    are_task.cancel()
    audit_are_task.cancel()
    for t in (consumer_task, are_task, audit_are_task):
        try:
            await t
        except asyncio.CancelledError:
            pass
    await redis.aclose()
    await engine.dispose()


app = FastAPI(
    title="ACP API Management Service",
    description="SaaS layer for API keys, security incident management, and durable event processing",
    version="3.0.0",
    lifespan=lifespan,
)

setup_app(app, "api-management")

app.include_router(api_key_router, prefix="/api-keys", tags=["API Keys"])
app.include_router(incident_router,                    tags=["Incidents"])
app.include_router(are_router,                         tags=["ARE"])
