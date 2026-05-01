from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.learning.models import BehaviorProfileModel


class LearningRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_profile(self, agent_id: uuid.UUID) -> BehaviorProfileModel | None:
        stmt = select(BehaviorProfileModel).where(
            BehaviorProfileModel.agent_id == agent_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create_profile(
        self, agent_id: uuid.UUID, tenant_id: uuid.UUID, **kwargs: Any  # noqa: ANN401
    ) -> BehaviorProfileModel:
        profile = BehaviorProfileModel(agent_id=agent_id, tenant_id=tenant_id, **kwargs)
        self.db.add(profile)
        await self.db.commit()
        await self.db.refresh(profile)
        return profile

    async def update_profile(
        self, agent_id: uuid.UUID, **kwargs: Any  # noqa: ANN401
    ) -> bool:
        stmt = (
            update(BehaviorProfileModel)
            .where(BehaviorProfileModel.agent_id == agent_id)
            .values(**kwargs)
        )
        await self.db.execute(stmt)
        await self.db.commit()
        return True
