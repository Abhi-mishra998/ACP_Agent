from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class LearningResult(BaseModel):
    """Result of adaptive behavior analysis."""

    agent_id: uuid.UUID
    tenant_id: uuid.UUID

    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    drift_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    reasons: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProbabilisticProfile(BaseModel):
    """Probabilistic view of agent behavior."""

    agent_id: uuid.UUID
    tool_usage_distribution: dict[str, int] = Field(default_factory=dict)
    transition_matrix: dict[str, dict[str, int]] = Field(default_factory=dict)
    avg_velocity: float = 0.0
    avg_tokens: float = 0.0
    baseline_risk: float = 0.0
    version: int = 1
