from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ActionType = Literal["KILL_AGENT", "ISOLATE_AGENT", "BLOCK_TOOL", "THROTTLE", "ALERT"]
Mode       = Literal["auto", "manual", "suggest"]
Severity   = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class AREConditions(BaseModel):
    """
    Typed conditions block for ARE rules.
    Accepts both dict format {"severity_in":[...]} and DSL list format
    [{"field":"severity","op":"in","value":[...]}] — the list form is
    converted before validation so legacy DB rows round-trip cleanly.
    extra="ignore" drops unknown keys so they cannot influence downstream logic.
    """
    model_config = ConfigDict(extra="ignore")

    window:           str   = "5m"
    min_violations:   int   = Field(default=1, ge=1)
    severity_in:      list[str] = Field(default_factory=list)
    risk_score_gte:   float = Field(default=0.0, ge=0.0, le=1.0)
    tool_in:          list[str] = Field(default_factory=list)
    agent_id:         str   = "*"
    repeat_offender:  bool  = False

    @model_validator(mode="before")
    @classmethod
    def normalize_list_format(cls, v: Any) -> Any:
        """Convert DSL list [{field,op,value}] → dict before field validation."""
        if not isinstance(v, list):
            return v
        result: dict[str, Any] = {}
        for item in v:
            if not isinstance(item, dict):
                continue
            field = item.get("field", "")
            op    = item.get("op", "")
            value = item.get("value")
            if field == "severity" and op == "in":
                result["severity_in"] = value if isinstance(value, list) else []
            elif field == "risk_score" and op in (">=", ">"):
                try:
                    result["risk_score_gte"] = float(value)
                except (TypeError, ValueError):
                    result["risk_score_gte"] = 0.0
            elif field == "tool" and op == "in":
                result["tool_in"] = value if isinstance(value, list) else []
            elif field == "agent_id" and op == "==":
                result["agent_id"] = str(value)
        return result

    @field_validator("severity_in", "tool_in", mode="before")
    @classmethod
    def coerce_null_to_empty(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if not isinstance(v, list):
            return []
        return [x for x in v if isinstance(x, str)]


class AutoResponseRuleCreate(BaseModel):
    name:                  str
    is_active:             bool          = True
    priority:              int           = Field(default=0,   ge=0,  le=1000)
    conditions:            AREConditions
    actions:               list[dict[str, Any]] = Field(default_factory=list)
    cooldown_seconds:      int           = Field(default=300, ge=0,  le=86400)
    max_triggers_per_hour: int           = Field(default=10,  ge=1,  le=1000)
    stop_on_match:         bool          = True
    mode:                  Mode          = "auto"


class AutoResponseRuleUpdate(BaseModel):
    name:                  str | None            = None
    is_active:             bool | None           = None
    priority:              int | None            = Field(default=None, ge=0, le=1000)
    conditions:            AREConditions | None  = None
    actions:               list[dict[str, Any]] | None = None
    cooldown_seconds:      int | None            = Field(default=None, ge=0, le=86400)
    max_triggers_per_hour: int | None            = Field(default=None, ge=1, le=1000)
    stop_on_match:         bool | None           = None
    mode:                  Mode | None           = None


class AutoResponseRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id:                    uuid.UUID
    tenant_id:             uuid.UUID
    name:                  str
    is_active:             bool
    priority:              int
    conditions:            AREConditions
    actions:               list[dict[str, Any]] = Field(default_factory=list)
    cooldown_seconds:      int
    max_triggers_per_hour: int
    stop_on_match:         bool
    mode:                  str
    version:               int
    trigger_count:         int
    false_positive_count:  int
    suppressed_until:      datetime | None
    last_triggered_at:     datetime | None
    created_at:            datetime
    updated_at:            datetime


class AREToggleRequest(BaseModel):
    enabled: bool

class AREToggleResponse(BaseModel):
    tenant_id: str
    enabled:   bool


class ARESimulateRequest(BaseModel):
    rule_id:    uuid.UUID
    time_range: str = "24h"


class ARESimulateMatchItem(BaseModel):
    incident_id: str
    agent_id:    str
    severity:    str
    risk_score:  float
    tool:        str | None
    created_at:  str


class ARESimulateResponse(BaseModel):
    rule_id:         str
    total_events:    int
    would_trigger:   int
    mitigated_pct:   float
    actions_preview: list[dict[str, Any]] = Field(default_factory=list)
    affected_agents: list[str]            = Field(default_factory=list)
    sample_matches:  list[ARESimulateMatchItem] = Field(default_factory=list)


# Evaluation trace — returned in audit logs and SSE events
class ConditionTrace(BaseModel):
    field:   str
    op:      str
    value:   Any
    actual:  Any
    passed:  bool


class EvaluationTrace(BaseModel):
    rule_id:             str
    rule_name:           str
    matched:             bool
    matched_conditions:  list[ConditionTrace] = Field(default_factory=list)
    failed_conditions:   list[ConditionTrace] = Field(default_factory=list)
    decision:            str
    actions_executed:    list[str]            = Field(default_factory=list)
    latency_ms:          float


# Rule version history entry (stored in version_history JSONB)
class RuleVersionEntry(BaseModel):
    version:    int
    changed_at: str
    changed_by: str
    snapshot:   dict[str, Any]


# Feedback / false-positive
class FeedbackRequest(BaseModel):
    trigger_ref:  str           # incident_id or request_id that was wrong
    reason:       str = ""
    suppress_min: int = Field(default=0, ge=0, le=1440)  # suppress rule for N minutes


class FeedbackResponse(BaseModel):
    rule_id:              str
    false_positive_count: int
    suppressed_until:     datetime | None


# Manual approval
class ApprovalRequest(BaseModel):
    approved: bool
    note:     str = ""
