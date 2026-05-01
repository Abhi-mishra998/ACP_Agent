"""
Autonomous Response Engine (ARE) — evaluation worker.

Architecture:
  - Rule pre-filtering via AREIndex (skip obviously non-matching rules)
  - All actions dispatched through AREExecutor (SDK enforcement layer)
  - Deterministic distributed locks per agent+rule (in AREExecutor)
  - Full evaluation audit: every decision logged, not just triggers
  - Incident correlation: skip if agent already being handled within TTL
  - P99 latency: per-rule Redis sorted set, 1-hour rolling window
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime

import httpx
import structlog

from sdk.common.config import settings
from services.api.are_executor import AREExecutor
from services.api.are_index import AREIndex

logger = structlog.get_logger(__name__)

_WINDOW_SECONDS: dict[str, int] = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}

# How long to suppress duplicate ARE processing for the same agent (correlation)
_CORR_TTL = 30  # seconds

# Backpressure: pause ARE consumer when stream backlog exceeds this
_MAX_STREAM_BACKLOG = 10_000


# ─────────────────────────────────────────────────────────────────────────────
# Condition evaluation — pure, traceable
# ─────────────────────────────────────────────────────────────────────────────

def _eval_one(field: str, op: str, rule_val: object, incident: dict, window_count: int) -> tuple[bool, object]:
    """Evaluate a single condition. Returns (passed, actual_value)."""
    FIELD_MAP = {
        "severity":        incident.get("severity", "LOW"),
        "risk_score":      float(incident.get("risk_score", 0)),
        "tool":            incident.get("tool") or "",
        "agent_id":        incident.get("agent_id", ""),
        "violation_count": int(incident.get("violation_count", 1)),
        "violations":      window_count,
        "risk_level":      incident.get("severity", "LOW").lower(),
    }
    actual = FIELD_MAP.get(field)
    if actual is None:
        return False, None

    try:
        if op == "==":     return actual == rule_val,            actual
        if op == "!=":     return actual != rule_val,            actual
        if op == ">":      return float(actual) > float(rule_val),  actual
        if op == ">=":     return float(actual) >= float(rule_val), actual
        if op == "<":      return float(actual) < float(rule_val),  actual
        if op == "<=":     return float(actual) <= float(rule_val), actual
        if op == "in":     return actual in rule_val,            actual
        if op == "not_in": return actual not in rule_val,        actual
    except Exception:
        pass
    return False, actual


def _check_condition(cond: dict, incident: dict, window_count: int) -> bool:
    """
    Supports both legacy blob format and new DSL list format.
    Legacy: {"severity_in": [...], "risk_score_gte": 0.7, ...}
    DSL:    [{"field": "severity", "op": "==", "value": "CRITICAL"}, ...]
    """
    if isinstance(cond, list):
        for item in cond:
            passed, _ = _eval_one(item["field"], item["op"], item["value"], incident, window_count)
            if not passed:
                return False
        return True

    # Legacy blob format (backward-compat)
    sev        = incident.get("severity", "LOW")
    risk       = float(incident.get("risk_score", 0))
    tool       = incident.get("tool") or ""
    agent_id   = incident.get("agent_id", "")
    viol_count = int(incident.get("violation_count", 1))

    if cond.get("severity_in") and sev not in cond["severity_in"]:
        return False
    if risk < float(cond.get("risk_score_gte", 0)):
        return False
    if cond.get("tool_in") and tool not in cond["tool_in"]:
        return False
    rule_agent = cond.get("agent_id", "*")
    if rule_agent != "*" and rule_agent != agent_id:
        return False
    if cond.get("repeat_offender") and viol_count < 2 and window_count < 2:
        return False
    if window_count < int(cond.get("min_violations", 1)):
        return False
    return True


def _build_trace(cond: dict, incident: dict, window_count: int) -> tuple[bool, list, list]:
    """Build per-condition match/fail trace. Returns (overall_match, matched_list, failed_list)."""
    matched, failed = [], []

    if isinstance(cond, list):
        for item in cond:
            passed, actual = _eval_one(item["field"], item["op"], item["value"], incident, window_count)
            entry = {"field": item["field"], "op": item["op"],
                     "value": item["value"], "actual": actual, "passed": passed}
            (matched if passed else failed).append(entry)
        return len(failed) == 0, matched, failed

    # Legacy: synthesise trace entries from blob
    checks = [
        ("severity",   "in",  cond.get("severity_in"),        incident.get("severity", "LOW")),
        ("risk_score", ">=",  cond.get("risk_score_gte", 0),  float(incident.get("risk_score", 0))),
        ("violations", ">=",  cond.get("min_violations", 1),  window_count),
    ]
    for field, op, rule_val, actual in checks:
        if field == "severity" and not cond.get("severity_in"):
            continue
        try:
            passed = (actual in (rule_val or [])) if op == "in" else float(actual) >= float(rule_val)
        except Exception:
            passed = False
        entry = {"field": field, "op": op, "value": rule_val, "actual": actual, "passed": passed}
        (matched if passed else failed).append(entry)

    return len(failed) == 0, matched, failed


# ─────────────────────────────────────────────────────────────────────────────
# Redis helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _window_count(redis, tenant_id: str, agent_id: str, window: str) -> int:
    now  = time.time()
    secs = _WINDOW_SECONDS.get(window, 300)
    key  = f"acp:{tenant_id}:are:violations:{agent_id}"
    try:
        await redis.zremrangebyscore(key, "-inf", now - secs)
        await redis.zadd(key, {f"{now:.3f}:{uuid.uuid4().hex[:6]}": now})
        count = int(await redis.zcard(key) or 0)
        await redis.expire(key, secs * 2)
        return count
    except Exception as exc:
        logger.warning("are_window_count_failed", error=str(exc))
        return 0


async def _is_enabled(redis, tenant_id: str) -> bool:
    try:
        val = await redis.get(f"acp:{tenant_id}:are:enabled")
        return val not in (b"0", "0")
    except Exception:
        return True


async def _is_suppressed(rule, now: datetime) -> bool:
    su = rule.suppressed_until
    if su is None:
        return False
    if su.tzinfo is None:
        from datetime import timezone
        su = su.replace(tzinfo=timezone.utc)
    return now < su


async def _incr_metric(redis, tenant_id: str, metric: str, label: str = "") -> None:
    key = f"acp:{tenant_id}:are:metrics:{metric}" + (f":{label}" if label else "")
    try:
        await redis.incr(key)
        await redis.expire(key, 86400)
    except Exception:
        pass


async def _record_latency(redis, tenant_id: str, rule_id: str, latency_ms: float) -> None:
    """Record latency sample to a rolling sorted set for P99 computation."""
    key = f"acp:{tenant_id}:are:latency:{rule_id}"
    now = time.time()
    try:
        member = f"{now:.3f}:{uuid.uuid4().hex[:4]}"
        await redis.zadd(key, {member: latency_ms})
        # Keep 1-hour window only
        await redis.zremrangebyscore(key, "-inf", latency_ms - 1)  # keep by score range
        # Cap to last 1000 samples
        await redis.zremrangebyrank(key, 0, -1001)
        await redis.expire(key, 3600)
    except Exception:
        pass


async def _check_backpressure(redis, stream_key: str) -> bool:
    """Returns True if backlog is too high (caller should pause)."""
    try:
        length = await redis.xlen(stream_key)
        return int(length or 0) > _MAX_STREAM_BACKLOG
    except Exception:
        return False


async def _check_correlation(redis, tenant_id: str, agent_id: str) -> bool:
    """Returns True if agent is already being handled (duplicate suppression)."""
    key = f"acp:{tenant_id}:are:agent_corr:{agent_id}"
    try:
        return bool(await redis.get(key))
    except Exception:
        return False


async def _mark_correlation(redis, tenant_id: str, agent_id: str) -> None:
    """Mark agent as currently being handled."""
    key = f"acp:{tenant_id}:are:agent_corr:{agent_id}"
    try:
        await redis.setex(key, _CORR_TTL, "1")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Full-decision audit (logs every evaluation outcome, not just triggers)
# ─────────────────────────────────────────────────────────────────────────────

async def _audit_decision(
    incident: dict,
    rule_id: str,
    rule_name: str,
    tenant_id: str,
    decision: str,
    actions_done: list[str],
    trace: dict,
) -> None:
    """Post all ARE decisions (trigger, no_match, suppressed, cooldown…) to audit service."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            await c.post(
                f"{settings.AUDIT_SERVICE_URL.rstrip('/')}/audit/logs",
                json={
                    "tenant_id":  tenant_id,
                    "agent_id":   incident.get("agent_id") or str(uuid.uuid4()),
                    "action":     "auto_response_eval",
                    "tool":       incident.get("tool", "unknown"),
                    "decision":   "deny" if decision == "triggered" else "allow",
                    "reason":     f"ARE rule '{rule_name}' → {decision}",
                    "request_id": incident.get("request_id"),
                    "metadata_json": {
                        "rule_id":        rule_id,
                        "rule_name":      rule_name,
                        "are_decision":   decision,
                        "actions":        actions_done,
                        "risk_score":     incident.get("risk_score", 0),
                        "source":         "auto_response_engine",
                        "trace":          trace,
                    },
                },
                headers={"X-Internal-Secret": settings.INTERNAL_SECRET,
                         "X-Tenant-ID": tenant_id},
            )
    except Exception as exc:
        logger.warning("are_audit_failed", decision=decision, error=str(exc))


async def _publish_sse(
    redis,
    tenant_id: str,
    incident: dict,
    rule_id: str,
    rule_name: str,
    actions: list[str],
    mode: str,
    trace: dict,
) -> None:
    try:
        await redis.publish(
            f"acp:tenant:{tenant_id}:events",
            json.dumps({
                "type":        "auto_response_executed",
                "tenant_id":   tenant_id,
                "agent_id":    incident.get("agent_id"),
                "incident_id": incident.get("id", ""),
                "rule_id":     rule_id,
                "rule_name":   rule_name,
                "mode":        mode,
                "actions":     actions,
                "severity":    incident.get("severity"),
                "timestamp":   datetime.now(UTC).isoformat(),
                "trace":       trace,
            }),
        )
    except Exception as exc:
        logger.warning("are_sse_failed", error=str(exc))


async def _store_pending_approval(
    redis, tenant_id: str, rule_id: str, incident: dict, actions: list[dict]
) -> None:
    approval_key = f"{rule_id}:{incident.get('request_id', uuid.uuid4().hex)}"
    key = f"acp:{tenant_id}:are:pending:{approval_key}"
    await redis.setex(key, 86400, json.dumps({
        "rule_id":      rule_id,
        "approval_key": approval_key,
        "incident":     incident,
        "actions":      actions,
        "created_at":   datetime.now(UTC).isoformat(),
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Core evaluation loop
# ─────────────────────────────────────────────────────────────────────────────

async def process_incident(redis, session_factory, incident: dict) -> None:
    """
    Evaluate all active ARE rules against one incident.

    Pipeline:
      enabled → backpressure → correlation → load rules → index pre-filter
      → per-rule: suppression → idempotency → cooldown → rate-limit
                  → window-count → build-trace → mode dispatch
      → full audit for every decision
    """
    tenant_id = str(incident.get("tenant_id", ""))
    agent_id  = str(incident.get("agent_id", ""))
    if not tenant_id or not agent_id:
        return

    if not await _is_enabled(redis, tenant_id):
        return

    # Backpressure: skip processing if queue is overloaded
    if await _check_backpressure(redis, "acp:incidents:queue"):
        logger.warning("are_backpressure_skip", tenant=tenant_id[:8])
        await _incr_metric(redis, tenant_id, "backpressure_skips")
        return

    # Incident correlation: skip if same agent is already being processed
    if await _check_correlation(redis, tenant_id, agent_id):
        await _incr_metric(redis, tenant_id, "correlation_skips")
        return
    await _mark_correlation(redis, tenant_id, agent_id)

    try:
        tenant_uuid = uuid.UUID(tenant_id)
    except ValueError:
        return

    incident_id = str(incident.get("request_id") or f"{agent_id[:8]}:{time.time():.0f}")
    now         = datetime.now(UTC)

    from services.api.repository.auto_response_rule import AutoResponseRuleRepository
    async with session_factory()() as db:
        rules = await AutoResponseRuleRepository(db).list(tenant_uuid, active_only=True)

    if not rules:
        return

    # Build index for cheap pre-filtering
    index    = AREIndex(rules)
    executor = AREExecutor(redis)
    float(incident.get("risk_score", 0))

    for rule in index.candidates(incident):
        rule_id   = str(rule.id)
        rule_name = rule.name
        t0        = time.perf_counter()

        # --- Suppression check ---
        if await _is_suppressed(rule, now):
            await _incr_metric(redis, tenant_id, "suppressed_total", rule_id[:8])
            await _audit_decision(incident, rule_id, rule_name, tenant_id,
                                  "suppressed", [], {"decision": "suppressed"})
            continue

        # --- Idempotency ---
        idemp_key = f"acp:{tenant_id}:are:idemp:{incident_id}:{rule_id}"
        if await redis.get(idemp_key):
            continue
        await redis.setex(idemp_key, 3600, "1")

        # --- Cooldown ---
        cond         = rule.conditions
        scope        = agent_id if (isinstance(cond, dict) and cond.get("agent_id", "*") != "*") else "global"
        cooldown_key = f"acp:{tenant_id}:are:cooldown:{rule_id}:{scope}"
        if await redis.get(cooldown_key):
            await _audit_decision(incident, rule_id, rule_name, tenant_id,
                                  "cooldown", [], {"decision": "cooldown"})
            continue

        # --- Rate limit ---
        hour     = int(time.time()) // 3600
        rate_key = f"acp:{tenant_id}:are:rate:{rule_id}:{hour}"
        if int(await redis.get(rate_key) or 0) >= rule.max_triggers_per_hour:
            logger.warning("are_rate_limit", rule_id=rule_id[:8])
            await _audit_decision(incident, rule_id, rule_name, tenant_id,
                                  "rate_limited", [], {"decision": "rate_limited"})
            continue

        # --- Rolling window count ---
        window = cond.get("window", "5m") if isinstance(cond, dict) else "5m"
        wcount = await _window_count(redis, tenant_id, agent_id, window)

        # --- Condition evaluation + trace ---
        matched, matched_conds, failed_conds = _build_trace(cond, incident, wcount)
        latency_ms = (time.perf_counter() - t0) * 1000

        if not matched:
            await _audit_decision(incident, rule_id, rule_name, tenant_id,
                                  "no_match", [], {
                                      "decision":          "no_match",
                                      "matched_conditions": matched_conds,
                                      "failed_conditions":  failed_conds,
                                      "latency_ms":         latency_ms,
                                  })
            continue

        # --- Record latency sample (for P99) ---
        await _record_latency(redis, tenant_id, rule_id, latency_ms)

        # --- Mode handling ---
        mode    = rule.mode or "auto"
        actions_done: list[str] = []
        decision = "triggered"

        if mode == "suggest":
            decision = "suggest"
            trace_payload = {
                "rule_id": rule_id, "rule_name": rule_name,
                "matched": True, "matched_conditions": matched_conds,
                "failed_conditions": failed_conds, "decision": decision,
                "actions_executed": [], "latency_ms": latency_ms,
            }
            await _publish_sse(redis, tenant_id, incident, rule_id, rule_name, [], mode, trace_payload)
            await _audit_decision(incident, rule_id, rule_name, tenant_id, decision, [], trace_payload)
            await _incr_metric(redis, tenant_id, "suggestions_total", rule_id[:8])
            if rule.stop_on_match:
                break
            continue

        if mode == "manual":
            decision = "manual_pending"
            await _store_pending_approval(redis, tenant_id, rule_id, incident, rule.actions)
            trace_payload = {
                "rule_id": rule_id, "rule_name": rule_name,
                "matched": True, "matched_conditions": matched_conds,
                "failed_conditions": failed_conds, "decision": decision,
                "actions_executed": [], "latency_ms": latency_ms,
            }
            await _publish_sse(redis, tenant_id, incident, rule_id, rule_name,
                               ["PENDING_APPROVAL"], mode, trace_payload)
            await _audit_decision(incident, rule_id, rule_name, tenant_id, decision, [], trace_payload)
            await _incr_metric(redis, tenant_id, "manual_pending_total", rule_id[:8])
            if rule.stop_on_match:
                break
            continue

        # mode == "auto" — execute via SDK executor
        ref = incident_id
        for action in rule.actions:
            desc = await executor.execute(action, incident, tenant_id, rule_id, ref)
            if desc:
                actions_done.append(desc)

        if not actions_done:
            continue

        # --- Trace payload ---
        trace_payload = {
            "rule_id": rule_id, "rule_name": rule_name,
            "matched": True, "matched_conditions": matched_conds,
            "failed_conditions": failed_conds, "decision": "triggered",
            "actions_executed": actions_done, "latency_ms": latency_ms,
        }

        # --- Post-execution bookkeeping ---
        await _audit_decision(incident, rule_id, rule_name, tenant_id,
                              "triggered", actions_done, trace_payload)
        await _publish_sse(redis, tenant_id, incident, rule_id, rule_name,
                           actions_done, mode, trace_payload)
        await redis.setex(cooldown_key, rule.cooldown_seconds, "1")
        await redis.incr(rate_key)
        await redis.expire(rate_key, 3600)

        async with session_factory()() as db:
            await AutoResponseRuleRepository(db).record_trigger(rule.id)

        await _incr_metric(redis, tenant_id, "triggers_total", rule_id[:8])

        logger.info("are_triggered",
                    rule=rule_name, agent=agent_id[:8],
                    actions=actions_done, latency_ms=round(latency_ms, 2))

        if rule.stop_on_match:
            break
