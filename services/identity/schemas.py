from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, SecretStr

# =========================
# REQUEST SCHEMAS
# =========================


class AgentLoginRequest(BaseModel):
    """Agent presents its ID + secret to obtain a JWT."""

    agent_id: uuid.UUID
    secret: SecretStr = Field(..., min_length=16, max_length=256)

    model_config = ConfigDict(from_attributes=True)



class CredentialCreateRequest(BaseModel):
    """Admin provisions credentials for an agent."""

    agent_id: uuid.UUID
    secret: SecretStr = Field(
        ...,
        min_length=16,
        max_length=256,
        description="Raw secret; will be hashed before storage",
    )

    model_config = ConfigDict(from_attributes=True)


# =========================
# RESPONSE SCHEMAS
# =========================


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    agent_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    tenant_id: uuid.UUID
    role: str = "agent"


class CredentialResponse(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    status: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str | None = None
    role: str
    tenant_id: uuid.UUID
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RevokeResponse(BaseModel):
    agent_id: uuid.UUID
    revoked: bool
    message: str


# =========================
# INTROSPECTION
# =========================


class TokenIntrospectRequest(BaseModel):
    token: str


class TokenIntrospectResponse(BaseModel):
    active: bool
    agent_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    tenant_id: uuid.UUID | None = None
    role: str | None = None
    exp: int | None = None
    iat: int | None = None


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)
    tenant_id: str
    org_id: str | None = None  # if omitted, defaults to tenant_id in the router
    role: str = "user"


class UserLogin(BaseModel):
    email: str
    password: str
