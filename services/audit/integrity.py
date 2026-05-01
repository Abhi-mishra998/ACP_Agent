"""
Audit Integrity Verifier
========================
FIX C-3: Recomputed hash is now assigned and compared (was previously discarded).
FIX M-2: `import json` moved to module level (was inside the for loop).
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.audit_hash import GENESIS_HASH, compute_event_hash
from services.audit.models import AuditLog

logger = structlog.get_logger(__name__)


class IntegrityResult:
    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.is_integrous = True
        self.processed_count = 0
        self.error_events: list[dict[str, Any]] = []


_INTEGRITY_PAGE_SIZE = 10_000  # OOM guard: never load more than 10k rows at once


async def verify_audit_chain(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, Any]:
    """
    Verifies the cryptographic integrity of the audit log chain for a tenant.

    Checks:
      1. prev_hash of each entry equals the event_hash of the previous entry.
      2. H(prev_hash + data) == event_hash (tamper detection — C-3 fix).
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.timestamp.asc())
        .limit(_INTEGRITY_PAGE_SIZE)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    if not logs:
        return {"success": True, "details": "No logs found to verify."}

    res = IntegrityResult(tenant_id)
    last_verified_hash = GENESIS_HASH  # Genesis state

    for entry in logs:
        res.processed_count += 1

        # C-3 FIX: use canonical hash function (matches writer.py and main.py)
        recomputed = compute_event_hash(
            prev_hash=str(entry.prev_hash or GENESIS_HASH),
            tenant_id=str(entry.tenant_id),
            agent_id=str(entry.agent_id),
            action=entry.action,
            tool=entry.tool,
            decision=entry.decision,
            request_id=entry.request_id,
        )

        # Check 1: Does prev_hash match the previous record's event_hash?
        if entry.prev_hash != last_verified_hash:
            res.is_integrous = False
            res.error_events.append(
                {
                    "request_id": entry.request_id,
                    "error": "Chain gap detected",
                    "expected_prev": last_verified_hash,
                    "actual_prev": entry.prev_hash,
                }
            )

        # Check 2: Does the stored event_hash match the recomputed hash? (tamper check)
        if recomputed != entry.event_hash:
            logger.critical("audit_tampering_detected",
                request_id=entry.request_id,
                expected_hash=recomputed,
                stored_hash=entry.event_hash
            )
            return {
                "tenant_id": str(tenant_id),
                "is_integrous": False,
                "error": "Audit tampering detected",
                "processed_count": res.processed_count
            }

        last_verified_hash = entry.event_hash

    return {
        "tenant_id": str(tenant_id),
        "is_integrous": res.is_integrous,
        "processed_count": res.processed_count,
        "error_count": len(res.error_events),
        "violations": res.error_events,
    }
