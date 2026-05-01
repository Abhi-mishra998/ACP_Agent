"""
ACP System Invariants
=====================
Fail-fast guards that MUST be called at every critical system boundary.

Rule: If a system invariant is violated, raise immediately with a clear message.
Never silently ignore a violation — security systems must be loud about failures.

Usage:
    from sdk.common.invariants import assert_risk_valid, assert_tenant_isolated
"""

from __future__ import annotations

import uuid


class InvariantViolation(RuntimeError):
    """Raised when a system invariant is violated. Always fatal — never catch this."""


def assert_risk_valid(score: float, context: str = "") -> None:
    """
    Risk score MUST always be in [0.0, 1.0].
    Any value outside this range means a bug in risk computation.
    """
    if not (0.0 <= score <= 1.0):
        raise InvariantViolation(
            f"Risk score {score!r} is outside [0.0, 1.0]. Context: {context or 'unknown'}. "
            "This is a critical bug — the scoring formula has a defect."
        )


def assert_tenant_isolated(
    resource_tenant_id: uuid.UUID,
    request_tenant_id: uuid.UUID,
    resource_type: str = "resource",
) -> None:
    """
    Tenant isolation MUST NEVER break.
    A request from tenant A must never access data belonging to tenant B.
    """
    if resource_tenant_id != request_tenant_id:
        raise InvariantViolation(
            f"Tenant isolation violation: {resource_type} belongs to tenant "
            f"{resource_tenant_id}, but request is from tenant {request_tenant_id}. "
            "This is a CRITICAL security bug."
        )


def assert_audit_required(action: str, audit_logged: bool, request_id: str) -> None:
    """
    Every non-ALLOW decision MUST produce an audit log.
    Skipping audit is a compliance violation and a security audit failure.
    """
    skip_exempt = {"allow"}
    if action.lower() not in skip_exempt and not audit_logged:
        raise InvariantViolation(
            f"Audit invariant violated: action={action!r} for request_id={request_id!r} "
            "was not logged. All non-ALLOW decisions require audit records."
        )


def assert_decision_exists(decision: object | None, request_id: str) -> None:
    """
    Every request through the security pipeline MUST produce a Decision.
    A None decision means the pipeline was bypassed or crashed silently.
    """
    if decision is None:
        raise InvariantViolation(
            f"Decision invariant violated: no Decision produced for request_id={request_id!r}. "
            "Every request must have an explicit allow/deny/throttle/escalate/kill verdict."
        )


def assert_org_consistency(
    org_id: uuid.UUID,
    tenant_id: uuid.UUID,
    context: str = "write operation",
) -> None:
    """
    SaaS Strict Invariant: org_id MUST always match tenant_id.
    This prevents cross-org leakage and ensures consistent policy evaluation.
    """
    if org_id != tenant_id:
        raise InvariantViolation(
            f"Org consistency violation during {context}: "
            f"org_id {org_id} does not match tenant_id {tenant_id}. "
            "This is a CRITICAL security bug indicating an attempted cross-tenant leak."
        )


def clamp_risk(score: float) -> float:
    """
    Hard-clamp a risk score to [0.0, 1.0].
    Use this at the OUTPUT of every risk computation to enforce the invariant.
    """
    return round(min(max(float(score), 0.0), 1.0), 4)
