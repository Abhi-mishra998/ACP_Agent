import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Header, Query, Request, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.auth import verify_internal_secret
from sdk.common.db import get_db, get_tenant_id
from sdk.common.deadline import check_deadline
from sdk.common.response import APIResponse
from sdk.common.audit_stream import push_audit_event
from sdk.common.redis import get_redis_client
from sdk.common.config import settings
from services.registry.repository import AgentRepository, PermissionRepository
from services.registry.schemas import (
    AgentCreate,
    AgentListResponse,
    AgentResponse,
    AgentUpdate,
    PermissionCreate,
    PermissionResponse,
)
from services.registry.service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"], dependencies=[Depends(verify_internal_secret)])
logger = structlog.get_logger()

async def get_redis():
    r = get_redis_client(settings.REDIS_URL)
    try:
        yield r
    finally:
        await r.aclose()


def get_agent_service(db: Annotated[AsyncSession, Depends(get_db)]) -> AgentService:
    repo = AgentRepository(db)
    perm_repo = PermissionRepository(db)
    return AgentService(repo, perm_repo)


# =========================
# AGENTS
# =========================


@router.post(
    "", response_model=APIResponse[AgentResponse], status_code=status.HTTP_201_CREATED
)
async def create_agent(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    payload: AgentCreate,
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[AgentResponse]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), owner_id=payload.owner_id
    )

    response = await service.create_agent(tenant_id, payload)
    
    # Enforce strict SaaS invariant: org_id == tenant_id
    from sdk.common.invariants import assert_org_consistency, InvariantViolation
    try:
        assert_org_consistency(response.org_id, tenant_id, "registry agent creation")
    except InvariantViolation as e:
        # P1: Immediate abort and DB rollback if invariant violated
        raise HTTPException(status_code=500, detail=str(e))
    
    # RULE 2: Every action is audited
    # P1-1 FIX: Removed __aenter__() anti-pattern; use client directly
    _redis = get_redis_client(settings.REDIS_URL)
    try:
        await push_audit_event(
            redis=_redis,
            tenant_id=tenant_id,
            agent_id=response.id,
            action="agent_registration",
            request_id=request_id,
            metadata={"name": response.name, "owner_id": response.owner_id}
        )
    finally:
        await _redis.aclose()

    bound_logger.info("agent_created", agent_id=str(response.id), name=response.name)
    return APIResponse(data=response)


@router.get("", response_model=APIResponse[AgentListResponse])
async def list_agents(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    owner_id: str | None = None,
    status_val: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[AgentListResponse]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(request_id=request_id, tenant_id=str(tenant_id))

    response = await service.list_agents(tenant_id, owner_id, status_val, page, size)
    bound_logger.info("agents_listed", count=len(response.data), total=response.total)
    return APIResponse(data=response)


@router.get(
    "/{agent_id}",
    response_model=APIResponse[AgentResponse],
    summary="Get detailed agent metadata",
)
async def get_agent(
    agent_id: uuid.UUID,
    service: Annotated[AgentService, Depends(get_agent_service)],
    tenant_id: uuid.UUID = Depends(get_tenant_id),
    request_id: str = Header(None, alias="X-Request-ID"),
) -> APIResponse[AgentResponse]:
    """Fetch metadata including current tool permissions and status."""
    agent_id_uuid = agent_id
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), agent_id=str(agent_id)
    )

    response = await service.get_agent(tenant_id, agent_id_uuid)
    bound_logger.info("agent_retrieved")
    return APIResponse(data=response)


@router.patch("/{agent_id}", response_model=APIResponse[AgentResponse])
async def update_agent(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    agent_id: uuid.UUID,
    payload: AgentUpdate,
) -> APIResponse[AgentResponse]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), agent_id=str(agent_id)
    )

    response = await service.update_agent(tenant_id, agent_id, payload)
    
    # RULE 2: Every action is audited
    # P1-1 FIX: Removed __aenter__() anti-pattern; use client directly
    _redis = get_redis_client(settings.REDIS_URL)
    try:
        await push_audit_event(
            redis=_redis,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action="agent_update",
            request_id=request_id,
            metadata={"updates": payload.model_dump(exclude_unset=True)}
        )
    finally:
        await _redis.aclose()

    bound_logger.info("agent_updated")
    return APIResponse(data=response)


@router.delete(
    "/{agent_id}", response_model=APIResponse[None], status_code=status.HTTP_200_OK
)
async def delete_agent(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    agent_id: uuid.UUID,
) -> APIResponse[None]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), agent_id=str(agent_id)
    )

    await service.delete_agent(tenant_id, agent_id)

    _redis = get_redis_client(settings.REDIS_URL)
    try:
        await push_audit_event(
            redis=_redis,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action="agent_delete",
            request_id=request_id,
            metadata={},
        )
    finally:
        await _redis.aclose()

    bound_logger.info("agent_deleted")
    return APIResponse(data=None)


# =========================
# PERMISSIONS
# =========================


@router.post(
    "/{agent_id}/permissions",
    response_model=APIResponse[PermissionResponse],
    status_code=status.HTTP_201_CREATED,
)
async def add_permission(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    agent_id: uuid.UUID,
    payload: PermissionCreate,
) -> APIResponse[PermissionResponse]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), agent_id=str(agent_id)
    )

    response = await service.add_permission(tenant_id, agent_id, payload)
    
    # RULE 2: Every action is audited
    # P1-1 FIX: Removed __aenter__() anti-pattern; use client directly
    _redis = get_redis_client(settings.REDIS_URL)
    try:
        await push_audit_event(
            redis=_redis,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action="permission_grant",
            tool=payload.tool_name,
            metadata={"permission_id": str(response.id), "action_type": payload.action}
        )
    finally:
        await _redis.aclose()

    bound_logger.info(
        "permission_added", permission_id=str(response.id), tool_name=response.tool_name
    )
    return APIResponse(data=response)


@router.get(
    "/{agent_id}/permissions",
    response_model=APIResponse[list[PermissionResponse]],
    status_code=status.HTTP_200_OK,
)
async def list_permissions(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    agent_id: uuid.UUID,
) -> APIResponse[list[PermissionResponse]]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id, tenant_id=str(tenant_id), agent_id=str(agent_id)
    )

    response = await service.get_agent_permissions(tenant_id, agent_id)
    bound_logger.info("permissions_listed", count=len(response))
    return APIResponse(data=response)


@router.delete(
    "/{agent_id}/permissions/{permission_id}",
    response_model=APIResponse[None],
    status_code=status.HTTP_200_OK,
)
async def revoke_permission(
    request: Request,
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    service: Annotated[AgentService, Depends(get_agent_service)],
    agent_id: uuid.UUID,
    permission_id: uuid.UUID,
) -> APIResponse[None]:
    request_id = getattr(request.state, "request_id", "unknown")
    bound_logger = logger.bind(
        request_id=request_id,
        tenant_id=str(tenant_id),
        agent_id=str(agent_id),
        permission_id=str(permission_id),
    )

    await service.remove_permission(tenant_id, agent_id, permission_id)

    # RULE 2: Every action is audited
    # P1-1 FIX: Removed __aenter__() anti-pattern; use client directly
    _redis = get_redis_client(settings.REDIS_URL)
    try:
        await push_audit_event(
            redis=_redis,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action="permission_revoke",
            request_id=request_id,
            metadata={"permission_id": str(permission_id)}
        )
    finally:
        await _redis.aclose()

    bound_logger.info("permission_deleted")
    return APIResponse(data=None)
