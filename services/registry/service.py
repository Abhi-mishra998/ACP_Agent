import contextlib
import uuid

from fastapi import HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.exc import IntegrityError

from services.registry.repository import AgentRepository, PermissionRepository
from services.registry.schemas import (
    AgentCreate,
    AgentListResponse,
    AgentResponse,
    AgentUpdate,
    PermissionCreate,
    PermissionResponse,
)

#: Set during application lifespan by the registry main.py startup handler.
_registry_redis: Redis | None = None


def set_registry_redis(redis: Redis) -> None:
    """Called once at startup to wire the Redis client into the service layer."""
    global _registry_redis
    _registry_redis = redis


async def _invalidate_agent_caches(agent_id: uuid.UUID) -> None:
    agent_meta_key = f"acp:agent:meta:{agent_id}"
    policy_pattern = f"acp:policy:*:a:{agent_id}:*"

    try:
        await _registry_redis.delete(agent_meta_key)
        # PE-1 FIX: use SCAN instead of KEYS (non-blocking)
        async for key in _registry_redis.scan_iter(match=policy_pattern, count=100):
            await _registry_redis.delete(key)
    except Exception:
        pass


class AgentService:
    def __init__(self, repo: AgentRepository, perm_repo: PermissionRepository) -> None:
        self.repo = repo
        self.perm_repo = perm_repo

    async def create_agent(
        self, tenant_id: uuid.UUID, payload: AgentCreate
    ) -> AgentResponse:
        existing = await self.repo.get_by_name(tenant_id, payload.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Agent with name '{payload.name}' already exists",
            )
        try:
            agent = await self.repo.create(tenant_id, payload)
            return AgentResponse.model_validate(agent)
        except IntegrityError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Integrity constraint violation during creation",
            ) from exc

    async def get_agent(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> AgentResponse:
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )
        return AgentResponse.model_validate(agent)

    async def list_agents(
        self,
        tenant_id: uuid.UUID,
        owner_id: str | None = None,
        status_val: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> AgentListResponse:
        agents, total = await self.repo.list(
            tenant_id=tenant_id,
            owner_id=owner_id,
            status=status_val,
            page=page,
            size=size,
        )

        pages = (total + size - 1) // size if size > 0 else 0

        return AgentListResponse(
            data=[AgentResponse.model_validate(a) for a in agents],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def update_agent(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, payload: AgentUpdate
    ) -> AgentResponse:
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )

        updated_agent = await self.repo.update(agent, payload)
        with contextlib.suppress(Exception):
            await _invalidate_agent_caches(agent_id)
        return AgentResponse.model_validate(updated_agent)

    async def delete_agent(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> None:
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )
        await self.repo.soft_delete(agent)
        with contextlib.suppress(Exception):
            await _invalidate_agent_caches(agent_id)

    async def add_permission(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, payload: PermissionCreate
    ) -> PermissionResponse:
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )

        try:
            permission = await self.perm_repo.create(tenant_id, agent_id, payload)
            with contextlib.suppress(Exception):
                await _invalidate_agent_caches(agent_id)
            return PermissionResponse.model_validate(permission)
        except IntegrityError as exc:
            # Composite unique key violation
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Permission for tool '{payload.tool_name}' "
                    "already exists for this agent"
                ),
            ) from exc

    async def remove_permission(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, permission_id: uuid.UUID
    ) -> None:
        # Just verifying agent exists isn't strictly necessary if permission exists
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )

        success = await self.perm_repo.delete(tenant_id, permission_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found",
            )
        with contextlib.suppress(Exception):
            await _invalidate_agent_caches(agent_id)

    async def get_agent_permissions(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID
    ) -> list[PermissionResponse]:
        agent = await self.repo.get_by_id(tenant_id, agent_id)
        if not agent or agent.deleted_at is not None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found",
            )

        permissions = await self.perm_repo.get_active_permissions(tenant_id, agent_id)
        return [PermissionResponse.model_validate(p) for p in permissions]
