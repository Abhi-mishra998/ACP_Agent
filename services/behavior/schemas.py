from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BehaviorAnalysis(BaseModel):
    """Result of real-time behavior analysis."""

    agent_id: uuid.UUID
    tenant_id: uuid.UUID

    # Legacy rule-based score (for backward compatibility)
    behavior_risk: float = Field(default=0.0, ge=0.0, le=1.0)

    # New probabilistic/adaptive signals
    anomaly_score: float = 0.0
    drift_score: float = 0.0
    cross_agent_risk: float = 0.0
    confidence: float = 0.0

    flags: list[str] = Field(default_factory=list)
    sequence: list[str] = Field(default_factory=list)
    velocity: float = 0.0  # requests per minute

    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(strict=True)
