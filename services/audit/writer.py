from __future__ import annotations

import structlog
from typing import Any
from sqlalchemy import desc, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.audit_hash import GENESIS_HASH, compute_event_hash
from sdk.utils import AUDIT_DUPLICATES_DROPPED_TOTAL, SLO_AUDIT_DURABILITY_TOTAL
from services.audit.models import AuditLog
from services.audit.schemas import AuditLogCreate

logger = structlog.get_logger(__name__)


class AuditWriter:
    """Service class for persisting audit logs with cryptographic integrity."""

    @staticmethod
    async def log(db: AsyncSession, redis: Any, payload: AuditLogCreate) -> AuditLog | None:
        """
        Idempotent audit logging with cryptographic chaining.
        Uses a PostgreSQL advisory lock (pg_advisory_xact_lock) to serialize chain
        writes per tenant across all workers — held for the duration of the transaction.
        """
        # Derive a stable int64 from the tenant UUID for the advisory lock.
        # This serializes chain writes for each tenant at the DB level without Redis.
        lock_key = int.from_bytes(payload.tenant_id.bytes[:8], "big") & 0x7FFFFFFFFFFFFFFF

        try:
            await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key})

            # 1. Fetch previous hash for this tenant to maintain the chain
            prev_stmt = (
                select(AuditLog.event_hash)
                .where(AuditLog.tenant_id == payload.tenant_id)
                .order_by(desc(AuditLog.timestamp), desc(AuditLog.id))
                .limit(1)
            )
            prev_result = await db.execute(prev_stmt)
            prev_hash: str = prev_result.scalar_one_or_none() or GENESIS_HASH

            # 2. Canonical hash — MUST match main.py consumer and integrity.py verifier
            event_hash = compute_event_hash(
                prev_hash=prev_hash,
                tenant_id=str(payload.tenant_id),
                agent_id=str(payload.agent_id),
                action=payload.action,
                tool=payload.tool,
                decision=payload.decision,
                request_id=payload.request_id,
            )

            # 3. Insert with ON CONFLICT handling
            data = payload.model_dump()
            data["prev_hash"] = prev_hash
            data["event_hash"] = event_hash
            
            # HARDENED: Explicitly set org_id from tenant_id for Core inserts
            if data.get("org_id") is None:
                data["org_id"] = data.get("tenant_id")

            stmt = (
                insert(AuditLog)
                .values(**data)
                .on_conflict_do_nothing(index_elements=["request_id", "event_hash"])
                .returning(AuditLog)
            )

            result = await db.execute(stmt)
            await db.commit()

            row = result.fetchone()

            if row is None:
                logger.info("audit_duplicate_detected", request_id=payload.request_id)
                AUDIT_DUPLICATES_DROPPED_TOTAL.inc()
                SLO_AUDIT_DURABILITY_TOTAL.labels(stage="duplicate_dropped").inc()
                return None

            SLO_AUDIT_DURABILITY_TOTAL.labels(stage="persisted").inc()
            return row[0]

        except Exception as exc:
            await db.rollback()
            logger.error(
                "audit_writer_error",
                error=str(exc),
                request_id=payload.request_id,
            )
            raise
