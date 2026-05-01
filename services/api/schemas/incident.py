from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Status   = Literal["OPEN", "INVESTIGATING", "MITIGATED", "ESCALATED", "RESOLVED"]
Trigger  = Literal["policy_deny", "kill", "escalate", "risk_threshold", "anomaly", "manual"]


class IncidentAction(BaseModel):
    type:      str
    by:        str
    note:      str | None = None
    timestamp: str


class IncidentCreate(BaseModel):
    tenant_id:  str
    agent_id:   str
    severity:   Severity
    trigger:    Trigger
    title:      str
    risk_score: float = 0.0
    tool:       str | None = None
    request_id: str | None = None
    reasons:    list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status:      Status | None = None
    assigned_to: str | None = None
    note:        str | None = None


class IncidentActionRequest(BaseModel):
    type: Literal["KILL_AGENT", "BLOCK_AGENT", "ISOLATE", "ESCALATE", "REASSIGN", "NOTE"]
    by:   str
    note: str | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id:                uuid.UUID
    incident_number:   str
    tenant_id:         uuid.UUID
    agent_id:          str
    severity:          str
    status:            str
    trigger:           str
    title:             str
    risk_score:        float
    tool:              str | None
    request_id:        str | None
    assigned_to:       str | None
    actions_taken:     list[Any]  = Field(default_factory=list)
    timeline:          list[Any]  = Field(default_factory=list)
    created_at:        datetime
    updated_at:        datetime
    resolved_at:       datetime | None
    acknowledged_at:   datetime | None = None
    mitigated_at:      datetime | None = None
    root_event_id:     str | None = None
    related_audit_ids: list[Any] = Field(default_factory=list)
    violation_count:   int = 1
    explanation:       str | None = None


class IncidentSummary(BaseModel):
    total:          int = 0
    open:           int = 0
    critical:       int = 0
    high:           int = 0
    mitigated:      int = 0
    resolved:       int = 0
    mttr_hours:     float = 0.0
    mtta_hours:     float = 0.0
    security_score: float = 100.0
    trend:          Literal["improving", "stable", "degrading"] = "stable"
