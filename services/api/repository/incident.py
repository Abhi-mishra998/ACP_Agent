from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.models.incident import Incident
from services.api.schemas.incident import IncidentCreate, IncidentUpdate

# ── State machine (Fix 4) ─────────────────────────────────────────────────────
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "OPEN":          {"INVESTIGATING"},
    "INVESTIGATING": {"MITIGATED", "ESCALATED", "RESOLVED"},
    "MITIGATED":     {"RESOLVED"},
    "ESCALATED":     {"MITIGATED", "RESOLVED"},
    "RESOLVED":      set(),
}

# ── Severity sort weight (Fix 7) ──────────────────────────────────────────────
_SEV_WEIGHT = case(
    (Incident.severity == "CRITICAL", 4),
    (Incident.severity == "HIGH",     3),
    (Incident.severity == "MEDIUM",   2),
    else_=1,
)


def _build_explanation(payload: IncidentCreate) -> str:
    """Human-readable summary (Fix 10)."""
    reasons = "; ".join(payload.reasons[:3]) if payload.reasons else "policy threshold exceeded"
    tool    = payload.tool or "unknown tool"
    return (
        f"Agent {payload.agent_id[:8]} attempted '{tool}' with risk score "
        f"{payload.risk_score:.0%} exceeding threshold. "
        f"Trigger: {payload.trigger}. Violations: {reasons}"
    )


class StateTransitionError(ValueError):
    """Raised when a requested status transition is not allowed."""


class IncidentRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _next_number(self) -> str:
        result = await self.db.execute(select(func.count()).select_from(Incident))
        n = (result.scalar() or 0) + 1
        return f"INC-{n:06d}"

    async def create(
        self,
        payload: IncidentCreate,
        *,
        dedup_key: str | None = None,
    ) -> Incident:
        now_iso = datetime.now(timezone.utc).isoformat()
        number  = await self._next_number()
        timeline_entry = {
            "event":     "incident_opened",
            "timestamp": now_iso,
            "detail":    f"Triggered by {payload.trigger}. Risk: {payload.risk_score:.2f}. Reasons: {'; '.join(payload.reasons)}",
        }
        incident = Incident(
            incident_number   = number,
            tenant_id         = uuid.UUID(payload.tenant_id),
            agent_id          = payload.agent_id,
            severity          = payload.severity,
            status            = "OPEN",
            trigger           = payload.trigger,
            title             = payload.title,
            risk_score        = payload.risk_score,
            tool              = payload.tool,
            request_id        = payload.request_id,
            root_event_id     = payload.request_id,    # audit link
            related_audit_ids = [],
            actions_taken     = [],
            timeline          = [timeline_entry],
            dedup_key         = dedup_key,
            violation_count   = 1,
            explanation       = _build_explanation(payload),
        )
        self.db.add(incident)
        await self.db.commit()
        await self.db.refresh(incident)
        return incident

    async def find_by_dedup_key(self, dedup_key: str, tenant_id: uuid.UUID) -> Incident | None:
        result = await self.db.execute(
            select(Incident).where(
                Incident.dedup_key == dedup_key,
                Incident.tenant_id == tenant_id,
                Incident.status.notin_(["RESOLVED"]),
            )
        )
        return result.scalar_one_or_none()

    async def bump_violation(self, incident_id: uuid.UUID) -> None:
        """Increment violation_count and append a de-dup timeline event."""
        result = await self.db.execute(select(Incident).where(Incident.id == incident_id))
        incident = result.scalar_one_or_none()
        if not incident:
            return
        incident.violation_count = (incident.violation_count or 1) + 1
        timeline = list(incident.timeline or [])
        timeline.append({
            "event":     "repeated_violation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail":    f"Duplicate event suppressed. Total occurrences: {incident.violation_count}",
        })
        incident.timeline = timeline
        await self.db.commit()

    async def get(self, incident_id: uuid.UUID, tenant_id: uuid.UUID) -> Incident | None:
        result = await self.db.execute(
            select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        tenant_id: uuid.UUID,
        status:   str | None = None,
        severity: str | None = None,
        limit:    int = 50,
        offset:   int = 0,
    ) -> tuple[list[Incident], int]:
        q = select(Incident).where(Incident.tenant_id == tenant_id)
        if status:
            q = q.where(Incident.status == status.upper())
        if severity:
            q = q.where(Incident.severity == severity.upper())

        # Fix 7: sort by severity weight DESC, then recency DESC
        q = q.order_by(_SEV_WEIGHT.desc(), Incident.created_at.desc())

        count_q = select(func.count()).select_from(q.subquery())
        total   = (await self.db.execute(count_q)).scalar() or 0
        result  = await self.db.execute(q.limit(limit).offset(offset))
        return list(result.scalars().all()), total

    async def update_status(
        self,
        incident_id: uuid.UUID,
        tenant_id:   uuid.UUID,
        payload:     IncidentUpdate,
        actor:       str,
    ) -> Incident | None:
        incident = await self.get(incident_id, tenant_id)
        if not incident:
            return None

        now     = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        timeline = list(incident.timeline or [])

        if payload.status:
            new_status = payload.status.upper()
            old_status = incident.status

            # Fix 4: Hard state machine enforcement
            allowed = _ALLOWED_TRANSITIONS.get(old_status, set())
            if new_status not in allowed:
                raise StateTransitionError(
                    f"Transition {old_status} → {new_status} not allowed. "
                    f"Permitted: {sorted(allowed) or ['none']}"
                )

            incident.status = new_status

            # Fix 8: Set SLA timestamps on transitions
            if new_status == "INVESTIGATING" and incident.acknowledged_at is None:
                incident.acknowledged_at = now
            if new_status == "MITIGATED" and incident.mitigated_at is None:
                incident.mitigated_at = now
            if new_status == "RESOLVED":
                incident.resolved_at = now

            timeline.append({
                "event":     "status_changed",
                "from":      old_status,
                "to":        new_status,
                "by":        actor,
                "timestamp": now_iso,
            })

        if payload.assigned_to is not None:
            incident.assigned_to = payload.assigned_to
            timeline.append({"event": "assigned", "to": payload.assigned_to, "by": actor, "timestamp": now_iso})

        if payload.note:
            timeline.append({"event": "note", "detail": payload.note, "by": actor, "timestamp": now_iso})

        incident.timeline = timeline
        await self.db.commit()
        await self.db.refresh(incident)
        return incident

    async def add_action(
        self,
        incident_id: uuid.UUID,
        tenant_id:   uuid.UUID,
        action_type: str,
        by:          str,
        note:        str | None,
    ) -> Incident | None:
        incident = await self.get(incident_id, tenant_id)
        if not incident:
            return None

        now_iso  = datetime.now(timezone.utc).isoformat()
        action   = {"type": action_type, "by": by, "note": note, "timestamp": now_iso}
        actions  = list(incident.actions_taken or [])
        timeline = list(incident.timeline or [])
        actions.append(action)
        timeline.append({"event": "action_taken", **action})
        incident.actions_taken = actions
        incident.timeline      = timeline
        await self.db.commit()
        await self.db.refresh(incident)
        return incident

    async def summary(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        rows = (await self.db.execute(
            select(Incident).where(Incident.tenant_id == tenant_id)
        )).scalars().all()

        total       = len(rows)
        by_status   = {"OPEN": 0, "INVESTIGATING": 0, "MITIGATED": 0, "ESCALATED": 0, "RESOLVED": 0}
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Fix 8: Use SLA timestamps for accurate MTTR
        resolved_durations: list[float] = []
        ack_durations:      list[float] = []

        for r in rows:
            by_status[r.status]     = by_status.get(r.status, 0) + 1
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

            if r.status == "RESOLVED" and r.resolved_at and r.created_at:
                created = r.created_at.replace(tzinfo=timezone.utc) if r.created_at.tzinfo is None else r.created_at
                delta   = (r.resolved_at - created).total_seconds() / 3600
                resolved_durations.append(delta)

            if r.acknowledged_at and r.created_at:
                created = r.created_at.replace(tzinfo=timezone.utc) if r.created_at.tzinfo is None else r.created_at
                ack_dur = (r.acknowledged_at - created).total_seconds() / 3600
                ack_durations.append(ack_dur)

        mttr     = round(sum(resolved_durations) / len(resolved_durations), 2) if resolved_durations else 0.0
        mtta     = round(sum(ack_durations)       / len(ack_durations),       2) if ack_durations       else 0.0

        # Fix 6: Weighted security score formula
        open_critical = sum(1 for r in rows if r.status in ("OPEN", "INVESTIGATING") and r.severity == "CRITICAL")
        open_high     = sum(1 for r in rows if r.status in ("OPEN", "INVESTIGATING") and r.severity == "HIGH")
        open_medium   = sum(1 for r in rows if r.status in ("OPEN", "INVESTIGATING") and r.severity == "MEDIUM")
        mttr_penalty  = min(20.0, max(0.0, (mttr - 4.0) * 2.0)) if mttr > 4.0 else 0.0
        repeated_pen  = min(10.0, sum(max(0, (r.violation_count or 1) - 1) for r in rows if r.status not in ("RESOLVED",)) * 0.5)

        score = max(0.0, 100.0
            - open_critical * 20
            - open_high     * 10
            - open_medium   * 3
            - mttr_penalty
            - repeated_pen
        )

        # Trend: compare open critical from last 24h vs older
        recent_critical = sum(
            1 for r in rows
            if r.severity == "CRITICAL" and r.status not in ("RESOLVED",)
        )
        trend = "stable"
        if recent_critical >= 3:
            trend = "degrading"
        elif score >= 85:
            trend = "improving"

        return {
            "total":          total,
            "open":           by_status["OPEN"],
            "investigating":  by_status["INVESTIGATING"],
            "escalated":      by_status.get("ESCALATED", 0),
            "mitigated":      by_status["MITIGATED"],
            "resolved":       by_status["RESOLVED"],
            "critical":       by_severity["CRITICAL"],
            "high":           by_severity["HIGH"],
            "medium":         by_severity["MEDIUM"],
            "low":            by_severity["LOW"],
            "mttr_hours":     mttr,
            "mtta_hours":     mtta,
            "security_score": round(score, 1),
            "trend":          trend,
        }
