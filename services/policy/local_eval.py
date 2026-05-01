"""
Local Policy Evaluator — Python port of services/policy/policies/agent_policy.rego

Evaluates agent permission policy in-process with no HTTP calls.
Target: p99 < 1ms (typically 5–50 µs).

Semantics are identical to the OPA policy:
  - Agent must be ACTIVE (not quarantined / terminated)
  - Risk score must be below 0.95
  - Tool must have an explicit ALLOW permission (or wildcard)
  - Any DENY overrides an ALLOW
  - Risk adjustment applied per agent risk_level + risk_score
"""
from __future__ import annotations

import time
from typing import Any


def evaluate(
    agent_status: str,
    permissions: list[dict[str, str]],
    tool: str,
    risk_score: float,
    risk_level: str = "low",
) -> tuple[bool, str, float]:
    """
    Evaluate the ACP agent policy locally.

    Args:
        agent_status:  Agent.status value ("active", "suspended", etc.)
        permissions:   List of {"tool_name": str, "action": str} dicts.
        tool:          The tool the agent is attempting to use.
        risk_score:    Inferred risk score in [0.0, 1.0].
        risk_level:    Agent risk classification ("low", "medium", "high").

    Returns:
        (allowed: bool, reason: str, risk_adjustment: float)
    """
    status = agent_status.lower()

    # Rule: agent must be active
    if status in ("quarantined", "terminated"):
        return False, "agent is suspended", 0.0

    if status != "active":
        return False, "agent is not active", 0.0

    # Rule: risk ceiling
    if risk_score >= 0.95:
        return False, "risk score exceeds critical threshold", 0.0

    # Rule: explicit DENY overrides everything
    has_deny = any(
        p.get("tool_name") == tool and p.get("action", "").upper() == "DENY"
        for p in permissions
    )
    if has_deny:
        return False, "explicit deny permission for tool", 0.0

    # Rule: must have matching ALLOW (exact tool or wildcard)
    has_allow = any(
        p.get("tool_name") in (tool, "*") and p.get("action", "").upper() == "ALLOW"
        for p in permissions
    )
    if not has_allow:
        return False, "no allow permission found for tool", 0.0

    # Risk adjustment (mirrors Rego risk_adjustment rules)
    rl = risk_level.lower()
    if rl == "high" and risk_score >= 0.5:
        adjustment = 0.2
    elif rl == "medium" and risk_score >= 0.7:
        adjustment = 0.15
    elif rl == "low" and risk_score < 0.2:
        adjustment = -0.1
    else:
        adjustment = 0.0

    return True, "permission granted", adjustment


def evaluate_from_jwt_claims(
    claims: dict[str, Any],
    tool: str,
    risk_score: float,
) -> tuple[bool, str, float]:
    """
    Convenience wrapper: extract agent data from decoded JWT claims and evaluate.
    Used by the gateway to avoid any Registry or Policy HTTP call.
    """
    agent_status = claims.get("agent_status", "active")
    permissions  = claims.get("permissions", [])
    risk_level   = claims.get("risk_level", "low")

    return evaluate(
        agent_status=agent_status,
        permissions=permissions,
        tool=tool,
        risk_score=risk_score,
        risk_level=risk_level,
    )


def timed_evaluate(
    agent_status: str,
    permissions: list[dict[str, str]],
    tool: str,
    risk_score: float,
    risk_level: str = "low",
) -> tuple[bool, str, float, float]:
    """
    Same as evaluate() but also returns wall-clock duration in milliseconds.
    Used by the performance test to assert p99 < 5ms.
    """
    t0 = time.perf_counter()
    result = evaluate(agent_status, permissions, tool, risk_score, risk_level)
    duration_ms = (time.perf_counter() - t0) * 1000
    return (*result, duration_ms)
