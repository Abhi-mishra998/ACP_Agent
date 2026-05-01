from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.db import get_db, get_tenant_id
from sdk.common.response import APIResponse
from services.api.repository.api_key import APIKeyRepository
from services.api.schemas.api_key import (
    APIKeyCreate,
    APIKeyGenerated,
    APIKeyResponse,
    APIKeyValidateRequest,
)

router = APIRouter(prefix="", tags=["api-keys"])


@router.post(
    "",
    response_model=APIResponse[APIKeyGenerated],
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new API Key",
)
async def create_api_key(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    payload: APIKeyCreate,
) -> APIResponse[APIKeyGenerated]:
    """
    Creates a new API key for the tenant.
    The raw key is returned in the 'api_key' field and will NOT be shown again.
    """
    repo = APIKeyRepository(db)
    api_key, raw_key = await repo.create(tenant_id, payload)

    return APIResponse(
        data=APIKeyGenerated(
            id=api_key.id,
            tenant_id=api_key.tenant_id,
            name=api_key.name,
            api_key=raw_key,
            key_prefix=api_key.key_prefix,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
        )
    )


@router.get("", response_model=APIResponse[list[APIKeyResponse]])
async def list_api_keys(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
) -> APIResponse[Sequence[APIKeyResponse]]:
    """List all active API keys for the current tenant."""
    repo = APIKeyRepository(db)
    keys = await repo.list_for_tenant(tenant_id)
    return APIResponse(data=[APIKeyResponse.model_validate(k) for k in keys])


@router.delete("/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_id: Annotated[uuid.UUID, Depends(get_tenant_id)],
    key_id: uuid.UUID,
) -> APIResponse[None]:
    """Revokes an API key, rendering it permanently inactive."""
    repo = APIKeyRepository(db)
    success = await repo.deactivate(tenant_id, key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found or belongs to another tenant",
        )
    return APIResponse(data=None)


@router.post("/validate", response_model=APIResponse[APIKeyResponse])
async def validate_api_key(
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: APIKeyValidateRequest,
) -> APIResponse[APIKeyResponse]:
    """Validates an API key and returns the associated tenant data."""
    repo = APIKeyRepository(db)
    api_key = await repo.validate(payload.api_key)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )
    return APIResponse(data=APIKeyResponse.model_validate(api_key))
