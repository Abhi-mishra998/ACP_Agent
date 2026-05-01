from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UsageBase(BaseModel):
    agent_id: uuid.UUID
    tool: str = Field(..., max_length=255)
    units: int = Field(1, ge=1)
    cost: float = Field(0.0, ge=0.0)


class UsageCreate(UsageBase):
    tenant_id: uuid.UUID


class UsageResponse(UsageBase):
    id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class UsageSummary(BaseModel):
    tenant_id: uuid.UUID
    total_units: int
    total_cost: float
    record_count: int
    money_saved: float = 0.0
    cost_prevented: float = 0.0
