import re
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sdk.common.enums import AgentStatus, PermissionAction


class PermissionCreate(BaseModel):
    tool_name: str = Field(..., max_length=150)
    action: PermissionAction = PermissionAction.ALLOW
    granted_by: str = Field(default="system", min_length=1, max_length=100)
    expires_at: datetime | None = None

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        # Allow snake_case (data_query), kebab-case (file-read), and dot notation (crm.read).
        # Reject whitespace, path traversal, and shell metacharacters only.
        if not re.match(r"^[a-z][a-z0-9_\-]*(\.[a-z][a-z0-9_\-]*)*$", v):
            raise ValueError(
                "Invalid tool_name. Use lowercase letters, digits, underscores, "
                "hyphens, or dots (e.g. 'data_query', 'crm.read')."
            )
        return v

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: datetime | None) -> datetime | None:
        if v is not None:
            now = datetime.now(tz=UTC)
            if v.tzinfo is None:
                v = v.replace(tzinfo=UTC)
            if v < now:
                raise ValueError("expires_at must be a future datetime")
        return v


class PermissionResponse(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    tool_name: str
    action: PermissionAction
    granted_by: str
    granted_at: datetime
    expires_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class AgentCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: str = Field(..., min_length=10, max_length=500)
    owner_id: str = Field(..., min_length=1, max_length=100)
    risk_level: str = Field("low", pattern="^(low|medium|high|critical)$")

    @field_validator("name")
    @classmethod
    def no_weird_chars(cls, v: str) -> str:
        if "<" in v or ">" in v:
            raise ValueError("Invalid characters")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9_-]{1,98}[a-z0-9]$", v):
            raise ValueError(
                "name must be 3-100 chars, lowercase a-z, 0-9, underscore, hyphen, "
                "and cannot start/end with a special character."
            )
        return v

    @field_validator("owner_id")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class AgentUpdate(BaseModel):
    description: str | None = Field(None, min_length=10, max_length=500)
    status: AgentStatus | None = None
    metadata_data: dict[str, str] | None = Field(None, alias="metadata")

    @field_validator("metadata_data")
    @classmethod
    def validate_metadata(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is not None:
            if len(v) > 20:
                raise ValueError("metadata can have a maximum of 20 keys")
            for k in v:
                if len(k) > 50:
                    raise ValueError("metadata keys must be <= 50 characters")
        return v


class AgentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    org_id: uuid.UUID
    name: str
    description: str
    owner_id: str
    status: AgentStatus
    risk_level: str = "low"
    metadata_data: dict = Field(default_factory=dict, serialization_alias="metadata")
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None
    permissions: list[PermissionResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class AgentListResponse(BaseModel):
    data: list[AgentResponse]
    total: int
    page: int
    size: int
    pages: int
