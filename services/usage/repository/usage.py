from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.usage.models.usage import UsageRecord
from services.usage.schemas.usage import UsageCreate, UsageSummary


class UsageRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def record(self, payload: UsageCreate) -> UsageRecord:
        record = UsageRecord(**payload.model_dump())
        self.db.add(record)
        await self.db.commit()
        await self.db.refresh(record)
        return record

    async def get_summary(self, tenant_id: uuid.UUID) -> UsageSummary:
        stmt = select(
            func.sum(UsageRecord.units).label("total_units"),
            func.sum(UsageRecord.cost).label("total_cost"),
            func.count(UsageRecord.id).label("record_count"),
        ).where(UsageRecord.tenant_id == tenant_id)
        result = await self.db.execute(stmt)
        row = result.first()

        # Calculate simulated ROI for UI synchronization
        # money_saved = total_cost * 0.15 (simulated mitigation value)
        # cost_prevented = total_units * 0.002 (simulated exfiltration prevention)
        total_units = row[0] or 0
        total_cost = row[1] or 0.0

        return UsageSummary(
            tenant_id=tenant_id,
            total_units=total_units,
            total_cost=total_cost,
            record_count=row[2] or 0,
            money_saved=round(total_cost * 0.15, 2),
            cost_prevented=round(total_units * 0.002, 2)
        )

    async def list_for_tenant(
        self, tenant_id: uuid.UUID, limit: int = 100
    ) -> Sequence[UsageRecord]:
        stmt = (
            select(UsageRecord)
            .where(UsageRecord.tenant_id == tenant_id)
            .order_by(UsageRecord.timestamp.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()
