import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from services.registry.models import Agent, AgentPermission
from services.registry.schemas import AgentCreate, AgentUpdate, PermissionCreate


class AgentRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, tenant_id: uuid.UUID, payload: AgentCreate) -> Agent:
        agent = Agent(tenant_id=tenant_id, **payload.model_dump())
        self.db.add(agent)
        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def get_by_id(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> Agent | None:
        stmt = (
            select(Agent)
            .options(selectinload(Agent.permissions))
            .where(Agent.id == agent_id, Agent.tenant_id == tenant_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name(self, tenant_id: uuid.UUID, name: str) -> Agent | None:
        stmt = (
            select(Agent)
            .options(selectinload(Agent.permissions))
            .where(Agent.name == name, Agent.tenant_id == tenant_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list(
        self,
        tenant_id: uuid.UUID,
        owner_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[Agent], int]:
        stmt = (
            select(Agent)
            .options(selectinload(Agent.permissions))
            .where(Agent.tenant_id == tenant_id)
        )
        if owner_id:
            stmt = stmt.where(Agent.owner_id == owner_id)
        if status:
            stmt = stmt.where(Agent.status == status)

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total_count = count_result.scalar_one()

        # Paginate
        offset = (page - 1) * size
        stmt = stmt.order_by(Agent.created_at.desc()).offset(offset).limit(size)
        result = await self.db.execute(stmt)

        return list(result.scalars().all()), total_count

    async def update(self, agent: Agent, payload: AgentUpdate) -> Agent:
        update_data = payload.model_dump(exclude_unset=True)
        if "metadata_data" in update_data:
            agent.metadata_data = update_data.pop("metadata_data")

        for key, value in update_data.items():
            setattr(agent, key, value)

        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def soft_delete(self, agent: Agent) -> Agent:
        agent.deleted_at = datetime.now(tz=UTC)
        await self.db.commit()
        await self.db.refresh(agent)
        return agent


class PermissionRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, payload: PermissionCreate
    ) -> AgentPermission:
        permission = AgentPermission(
            tenant_id=tenant_id, agent_id=agent_id, **payload.model_dump()
        )
        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)
        return permission

    async def list_for_agent(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> list[AgentPermission]:
        stmt = select(AgentPermission).where(
            AgentPermission.agent_id == agent_id, AgentPermission.tenant_id == tenant_id
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def delete(self, tenant_id: uuid.UUID, permission_id: uuid.UUID) -> bool:
        stmt = delete(AgentPermission).where(
            AgentPermission.id == permission_id, AgentPermission.tenant_id == tenant_id
        )
        result = await self.db.execute(stmt)
        await self.db.commit()
        return bool(result.rowcount > 0)  # type: ignore[attr-defined]

    async def get_active_permissions(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> list[AgentPermission]:
        now = datetime.now(tz=UTC)
        stmt = select(AgentPermission).where(
            AgentPermission.agent_id == agent_id,
            AgentPermission.tenant_id == tenant_id,
            (AgentPermission.expires_at.is_(None)) | (AgentPermission.expires_at > now),
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
