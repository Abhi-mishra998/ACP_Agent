from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditLogBase(BaseModel):
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    action: str = Field(..., max_length=100)
    tool: str | None = Field(None, max_length=255)
    decision: str = Field(..., max_length=50)
    reason: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(None, max_length=50)
    event_hash: str | None = Field(None, max_length=64)
    prev_hash: str | None = Field(None, max_length=64)


class AuditLogCreate(AuditLogBase):
    pass


class AuditLogSearch(BaseModel):
    agent_id: uuid.UUID | None = None
    action: str | None = None
    tool: str | None = None
    decision: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    metadata_filter: dict[str, Any] | None = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)


class AuditLogResponse(AuditLogBase):
    id: uuid.UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AuditLogResponse]


class AuditSummaryResponse(BaseModel):
    total_calls: int
    total_denials: int
    active_agents_count: int
    most_used_tool: str | None = None
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    avg_risk_score: float = 0.0
    requests_by_hour: list[int] = Field(default_factory=list)
    risk_distribution: dict[str, int] = Field(default_factory=dict)
    threats_blocked: int = 0
    high_risk_agents: int = 0
    metadata: dict = Field(default_factory=dict)
