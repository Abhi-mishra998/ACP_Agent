from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit.models import AuditLog


class AuditAggregator:
    """
    Computes time-series insights and behavioral trends from the audit logs.
    Powers the 'Risk Dashboard' data layer.
    """

    @staticmethod
    async def get_top_risky_agents(db: AsyncSession, tenant_id: uuid.UUID, limit: int = 10) -> list[dict[str, Any]]:
        """
        Identify agents with the highest density of security blocks/escalations.
        """
        # Decisions that indicate risk
        # M-12 fix: 'decision' column contains 'deny'/'allow'.
        # 'killed' and 'behavior_firewall_decision' are in the 'action' column.
        stmt = (
            select(
                AuditLog.agent_id,
                func.count(AuditLog.id).label("threat_count"),
                func.avg(sa.cast(AuditLog.metadata_json["risk_score"].as_string(), sa.Float)).label("avg_risk")
            )
            .where(AuditLog.tenant_id == tenant_id)
            .where(
                or_(
                    AuditLog.decision == "deny",
                    AuditLog.decision == "escalate",
                    AuditLog.action.in_(["killed", "behavior_firewall_decision"]),
                )
            )
            .group_by(AuditLog.agent_id)
            .order_by(desc("threat_count"))
            .limit(limit)
        )

        result = await db.execute(stmt)
        return [
            {
                "agent_id": str(row.agent_id),
                "threat_count": row.threat_count,
                "avg_risk_score": round(row.avg_risk or 0.0, 2)
            }
            for row in result
        ]

    @staticmethod
    async def get_anomaly_trends(db: AsyncSession, tenant_id: uuid.UUID, days: int = 7) -> list[dict[str, Any]]:
        """
        M-1 fix: 'days' parameter now applied as a time-range filter.
        Calculate daily threat trends for the dashboard chart.
        """
        since = datetime.now(tz=UTC) - timedelta(days=days)
        stmt = (
            select(
                func.date_trunc('day', AuditLog.timestamp).label("day"),
                func.count(AuditLog.id).label("count")
            )
            .where(AuditLog.tenant_id == tenant_id)
            .where(AuditLog.timestamp >= since)
            .where(AuditLog.decision.in_(["deny", "escalate"]))
            .group_by("day")
            .order_by("day")
        )

        result = await db.execute(stmt)
        return [
            {"date": row.day.isoformat(), "count": row.count}
            for row in result
        ]
