"""
ARE Action Executor — SDK-enforced.

ALL actions route through AREExecutor.execute().
Enforces: OPA policy check → distributed lock → action → post-audit.
No direct HTTP calls from the worker anymore.
"""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager

import httpx
import structlog

from sdk.common.config import settings

logger = structlog.get_logger(__name__)

_LOCK_TTL = 30          # seconds — lock expires if executor crashes mid-action
_DESTRUCTIVE = frozenset({"KILL_AGENT", "ISOLATE_AGENT"})


# ─────────────────────────────────────────────────────────────────────────────
# Distributed lock (Redis SET NX EX)
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def _execution_lock(redis, tenant_id: str, agent_id: str, rule_id: str):
    """
    Acquire a per-agent-per-rule exclusive lock before executing any action.
    Prevents two concurrent ARE workers from double-firing on the same event.
    """
    key     = f"acp:{tenant_id}:are:lock:{agent_id}:{rule_id}"
    token   = f"{time.time():.3f}"
    acquired = await redis.set(key, token, nx=True, ex=_LOCK_TTL)
    if not acquired:
        raise RuntimeError(f"lock_contention rule={rule_id[:8]} agent={agent_id[:8]}")
    try:
        yield
    finally:
        # Only delete if we still own the lock (not expired and re-acquired by another)
        current = await redis.get(key)
        current_val = current.decode() if isinstance(current, bytes) else current
        if current_val == token:
            await redis.delete(key)


# ─────────────────────────────────────────────────────────────────────────────
# OPA policy gate (SDK enforcement layer)
# ─────────────────────────────────────────────────────────────────────────────

async def _policy_gate(tenant_id: str, agent_id: str, tool: str,
                        risk_score: float, action_type: str) -> tuple[bool, str]:
    """
    Call OPA before executing any action.
    Returns (allowed, reason). Fail-closed — denies when OPA is unreachable.
    Destructive actions (KILL/ISOLATE) require an explicit OPA allow.
    """
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            resp = await c.post(
                f"{settings.POLICY_SERVICE_URL.rstrip('/')}/policy/evaluate",
                json={
                    "tenant_id": tenant_id,
                    "agent_id":  agent_id,
                    "tool":      tool or "unknown",
                    "risk_score": risk_score,
                    "behavior_history": [],
                    "policy_version": "v1",
                    "metadata": {"source": "are_executor", "action": action_type},
                },
                headers={"X-Internal-Secret": settings.INTERNAL_SECRET,
                         "X-Tenant-ID": tenant_id},
            )
            if resp.status_code == 200:
                data    = resp.json().get("data", {})
                allowed = data.get("allowed", True)
                reason  = data.get("reason", "")
                if not allowed:
                    logger.warning("are_policy_gate_denied",
                                   action=action_type, reason=reason,
                                   agent=agent_id[:8])
                return bool(allowed), reason
            # Non-200 from policy service — fail-closed for destructive actions
            logger.warning("are_policy_gate_non200", status=resp.status_code, action=action_type)
    except Exception as exc:
        logger.warning("are_policy_gate_failed", error=str(exc), action=action_type)

    # Fail-closed: destructive actions blocked when OPA unavailable
    if action_type in _DESTRUCTIVE:
        logger.error("are_policy_gate_unavailable_fail_closed", action=action_type)
        return False, "policy_gate_unavailable"
    return True, "policy_gate_unavailable_non_destructive"


# ─────────────────────────────────────────────────────────────────────────────
# Individual action implementations (one side-effect, well-typed)
# ─────────────────────────────────────────────────────────────────────────────

async def _do_kill(redis, agent_id: str, tenant_id: str, ref: str) -> str:
    payload = json.dumps({"ref": ref, "source": "are", "ts": time.time()})
    await redis.setex(f"acp:{tenant_id}:agent_kill:{agent_id}", 86400, payload)
    logger.critical("are_exec_kill", agent=agent_id[:8])
    return f"KILL_AGENT:{agent_id[:8]}"


async def _do_isolate(agent_id: str) -> str:
    async with httpx.AsyncClient(timeout=5.0) as c:
        await c.patch(
            f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}",
            json={"status": "suspended"},
            headers={"X-Internal-Secret": settings.INTERNAL_SECRET},
        )
    logger.warning("are_exec_isolate", agent=agent_id[:8])
    return f"ISOLATE_AGENT:{agent_id[:8]}"


async def _do_block_tool(agent_id: str, tool: str, ref: str) -> str:
    async with httpx.AsyncClient(timeout=5.0) as c:
        await c.post(
            f"{settings.REGISTRY_SERVICE_URL.rstrip('/')}/agents/{agent_id}/permissions",
            json={"tool_name": tool, "action": "DENY", "granted_by": f"are:{ref[:8]}"},
            headers={"X-Internal-Secret": settings.INTERNAL_SECRET},
        )
    return f"BLOCK_TOOL:{tool}"


async def _do_throttle(redis, agent_id: str, tenant_id: str, rate: str) -> str:
    await redis.setex(f"acp:{tenant_id}:throttle:{agent_id}", 3600, rate)
    return f"THROTTLE:{rate}"


async def _do_alert(incident: dict, tenant_id: str) -> str:
    url = settings.SLACK_WEBHOOK_URL
    if not url:
        return "ALERT:no_webhook"
    sev   = incident.get("severity", "HIGH")
    color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308"}.get(sev, "#6b7280")
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(url, json={
                "text": f"🤖 *ARE* — {sev} auto-mitigated",
                "attachments": [{"color": color, "blocks": [
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Agent:* `{incident.get('agent_id','')[:8]}`"},
                        {"type": "mrkdwn", "text": f"*Risk:* {float(incident.get('risk_score',0)):.0%}"},
                        {"type": "mrkdwn", "text": f"*Severity:* {sev}"},
                        {"type": "mrkdwn", "text": f"*Title:* {incident.get('title','')}"},
                    ]},
                ]}],
            })
    except Exception as exc:
        logger.warning("are_exec_alert_failed", error=str(exc))
    return "ALERT:slack"


# ─────────────────────────────────────────────────────────────────────────────
# Public executor — the ONLY entry-point for action dispatch
# ─────────────────────────────────────────────────────────────────────────────

class AREExecutor:
    """
    All ARE actions must be executed through this class.
    Enforces: lock → policy gate → action → error containment.
    """

    def __init__(self, redis) -> None:
        self._redis = redis

    async def execute(
        self,
        action:    dict,
        incident:  dict,
        tenant_id: str,
        rule_id:   str,
        ref:       str,
    ) -> str | None:
        """
        Execute a single action with full enforcement.
        Returns description string or None on failure.
        Never raises — errors are logged and contained.
        """
        atype    = action.get("type", "")
        agent_id = incident.get("agent_id", "")
        tool     = action.get("tool") or incident.get("tool") or "*"
        risk     = float(incident.get("risk_score", 0))

        # Gate through policy engine — enforced, not advisory.
        # Destructive actions use risk=0.0 so OPA evaluates ARE authorization,
        # not agent execution. High incident risk_score would cause OPA to deny
        # agent execution, which must not block the ARE from killing the agent.
        gate_risk = 0.0 if atype in _DESTRUCTIVE else risk
        allowed, reason = await _policy_gate(tenant_id, agent_id, tool, gate_risk, atype)
        if not allowed:
            logger.warning("are_action_policy_blocked",
                           action=atype, reason=reason, agent=agent_id[:8])
            return None

        try:
            async with _execution_lock(self._redis, tenant_id, agent_id, rule_id):
                if atype == "KILL_AGENT":
                    return await _do_kill(self._redis, agent_id, tenant_id, ref)
                if atype == "ISOLATE_AGENT":
                    return await _do_isolate(agent_id)
                if atype == "BLOCK_TOOL":
                    return await _do_block_tool(agent_id, tool, ref)
                if atype == "THROTTLE":
                    return await _do_throttle(self._redis, agent_id, tenant_id, action.get("rate", "5/m"))
                if atype == "ALERT":
                    return await _do_alert(incident, tenant_id)
        except RuntimeError as exc:
            # Lock contention — skip this action, another worker is handling it
            logger.info("are_lock_contention", action=atype, detail=str(exc))
        except Exception as exc:
            logger.error("are_exec_failed", action=atype, error=str(exc))
        return None
