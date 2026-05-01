"""
ACP Decision Schemas
====================
Canonical input/output types for the unified DecisionEngine.

DecisionContext  → Input  (what the engine receives)
Decision         → Output (what the engine produces)
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExecutionAction(StrEnum):
    ALLOW    = "allow"
    MONITOR  = "monitor"
    THROTTLE = "throttle"
    REDACT   = "redact"
    ESCALATE = "escalate"
    KILL     = "kill"
    DENY     = "deny"  # kept for backward compat with policy returns


class OrchestrationRequest(BaseModel):
    """
    Minimal context payload sent by the Gateway to prompt Decision Engine Orchestration.
    """
    tenant_id: uuid.UUID
    agent_id: uuid.UUID
    tool: str
    tokens: int = 0
    inference_risk: float = 0.0
    inference_flags: list[str] = Field(default_factory=list)
    request_id: str = ""
    payload_hash: str = ""
    cost_risk: float = 0.0
    client_ip: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionContext(BaseModel):
    """
    Full context provided to DecisionEngine.evaluate().
    All risk signals are normalised to [0.0, 1.0].
    """

    # Identity
    tenant_id:  uuid.UUID
    agent_id:   uuid.UUID
    tool:       str
    request_id: str = ""

    # Policy signal
    policy_allowed: bool    = True
    policy_reason:  str | None = None
    policy_risk_adjustment: float = 0.0

    # Risk signals [0.0–1.0 each]
    inference_risk:   float = Field(default=0.0, ge=0.0, le=1.0)
    behavior_risk:    float = Field(default=0.0, ge=0.0, le=1.0)
    anomaly_score:    float = Field(default=0.0, ge=0.0, le=1.0)
    cost_risk:        float = Field(default=0.0, ge=0.0, le=1.0)
    cross_agent_risk: float = Field(default=0.0, ge=0.0, le=1.0)

    # Confidence and learning signals
    confidence:          float = Field(default=1.0, ge=0.0, le=1.0)
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    true_positive_count: int   = 0

    # Flags collected from sub-systems
    behavior_flags:  list[str]       = Field(default_factory=list)
    inference_flags: list[str]       = Field(default_factory=list)
    usage_metrics:   dict[str, Any]  = Field(default_factory=dict)

    model_config = ConfigDict(strict=False)


class Decision(BaseModel):
    """
    The verdict produced by DecisionEngine.evaluate().
    This is the canonical output for the entire ACP pipeline.
    """

    action:     ExecutionAction
    risk:       float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reasons:    list[str]        = Field(default_factory=list)
    signals:    dict[str, float] = Field(default_factory=dict)
    metadata:   dict[str, Any]   = Field(default_factory=dict)

    model_config = ConfigDict(strict=False)


# ---------------------------------------------------------------------------
# Backward-Compat Alias (DecisionRequest → DecisionContext)
# Callers that still use DecisionRequest will continue to work.
# ---------------------------------------------------------------------------

class DecisionRequest(DecisionContext):
    """Deprecated alias for DecisionContext. Use DecisionContext in new code."""
    # Extra fields from old schema kept for replay compat
    drift_score: float = Field(default=0.0, ge=0.0, le=1.0)

    model_config = ConfigDict(strict=False)
