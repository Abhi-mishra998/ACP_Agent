from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# =========================
# PERMISSION (mirrors registry model)
# =========================


class PermissionInput(BaseModel):
    tool_name: str
    action: str  # "allow" or "deny"
    granted_by: uuid.UUID
    expires_at: datetime | None = None

    model_config = ConfigDict(strict=False)


# =========================
# AGENT INPUT (passed to OPA)
# =========================


class AgentInput(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    risk_level: str
    permissions: list[PermissionInput] = Field(default_factory=list)

    model_config = ConfigDict(strict=False)


# =========================
# EVALUATION REQUEST
# =========================


class EvaluationRequest(BaseModel):
    """
    Input to the policy evaluation endpoint.
    Includes metadata for multi-layer decision architecture.
    """

    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    tool: str = Field(..., min_length=1, max_length=255)
    policy_version: str = Field("v1", max_length=20)

    # Metadata for OPA context
    request_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict) # Future attributes (IP, region)

    agent: AgentInput | None = None  # pre-resolved by gateway; if None, policy fetches it

    # JWT-embedded claims forwarded by the gateway — if present, skip Registry fetch
    agent_claims: dict[str, Any] | None = Field(
        default=None,
        description="JWT-embedded agent metadata forwarded by gateway to skip Registry HTTP call",
    )

    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    behavior_history: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(strict=False)


# =========================
# EVALUATION RESPONSE
# =========================


class EvaluationResponse(BaseModel):
    agent_id: uuid.UUID
    tool: str
    allowed: bool
    reason: str
    risk_adjustment: float = 0.0
    evaluated_at: datetime


# =========================
# POLICY SIMULATION
# =========================

class PolicyCondition(BaseModel):
    field:    str   # risk_score | tool | inference_risk | behavior_risk | anomaly_score
    operator: str   # gt | gte | lt | lte | eq | neq
    value:    str

class PolicyRule(BaseModel):
    conditions:  list[PolicyCondition]
    action:      str  # DENY | ALLOW | MONITOR | THROTTLE | ESCALATE
    description: str = ""

class SimulateRequest(BaseModel):
    policy:     list[PolicyRule]
    agent_id:   uuid.UUID
    time_range: str = "24h"   # 1h | 6h | 24h | 7d

class SimulateDiffItem(BaseModel):
    event_id:    str
    tool:        str
    timestamp:   str
    risk_score:  float
    old_decision: str
    new_decision: str

class SimulateResponse(BaseModel):
    total_events: int
    would_allow:  int
    would_deny:   int
    no_change:    int
    diff:         list[SimulateDiffItem]
