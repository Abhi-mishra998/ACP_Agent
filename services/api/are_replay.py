"""
ARE Replay Engine — re-evaluate historical audit events through current rules.

Fetches audit log entries from the Audit service API (correct DB), converts
them to incident-shaped dicts, and runs them through the ARE condition engine
in dry-run mode (no actions executed, results returned in the response).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from sdk.common.config import settings
from services.api.are_worker import _build_trace

logger = structlog.get_logger(__name__)

_AUDIT_BASE = settings.AUDIT_SERVICE_URL.rstrip("/")


def _log_to_incident(row: dict) -> dict:
    """Convert an audit log dict (from Audit API) to an ARE incident-shaped dict."""
    meta = row.get("metadata_json") or {}
    if isinstance(meta, str):
        import json
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    return {
        "tenant_id":       row.get("tenant_id", ""),
        "agent_id":        row.get("agent_id", ""),
        "tool":            row.get("tool") or "unknown",
        "severity":        meta.get("severity", meta.get("risk_level", "LOW")).upper(),
        "risk_score":      float(meta.get("risk_score", 0)),
        "violation_count": int(meta.get("violation_count", 1)),
        "request_id":      row.get("request_id") or str(uuid.uuid4()),
        "title":           row.get("reason") or "",
        "created_at":      row.get("timestamp", ""),
    }


async def replay_rules(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    rule_ids: list[uuid.UUID] | None = None,
    hours: int = 24,
    limit: int = 500,
) -> dict:
    """
    Dry-run ARE rules against historical audit log entries.

    Fetches logs from the Audit service API to avoid cross-DB access.
    """
    from services.api.repository.auto_response_rule import AutoResponseRuleRepository

    repo  = AutoResponseRuleRepository(db)
    rules = await repo.list(tenant_id, active_only=True)
    if rule_ids:
        rule_id_set = {str(r) for r in rule_ids}
        rules = [r for r in rules if str(r.id) in rule_id_set]

    if not rules:
        return {"total_events": 0, "matches_per_rule": {}, "sample_matches": [], "summary": "no rules"}

    # Fetch audit logs from Audit service (correct DB)
    logs: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{_AUDIT_BASE}/logs",
                params={"limit": min(limit, 500), "offset": 0},
                headers={
                    "X-Internal-Secret": settings.INTERNAL_SECRET,
                    "X-Tenant-ID": str(tenant_id),
                },
            )
            if resp.status_code == 200:
                body = resp.json()
                items = body.get("data", {}).get("items", [])
                since = datetime.now(UTC) - timedelta(hours=hours)
                for item in items:
                    ts_str = item.get("timestamp", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if ts < since:
                                continue
                        except Exception:
                            pass
                    logs.append(item)
    except Exception as exc:
        logger.warning("replay_audit_fetch_failed", error=str(exc))
        return {"total_events": 0, "matches_per_rule": {}, "sample_matches": [], "summary": f"audit fetch error: {exc}"}

    matches_per_rule: dict[str, dict] = {
        str(r.id): {"rule_name": r.name, "matches": 0, "samples": []}
        for r in rules
    }
    total_events = len(logs)

    for log_row in logs:
        incident = _log_to_incident(log_row)
        for rule in rules:
            rid = str(rule.id)
            matched, matched_conds, _ = _build_trace(
                rule.conditions, incident, window_count=0
            )
            if matched:
                matches_per_rule[rid]["matches"] += 1
                if len(matches_per_rule[rid]["samples"]) < 5:
                    matches_per_rule[rid]["samples"].append({
                        "log_id":             log_row.get("id", ""),
                        "agent_id":           incident["agent_id"],
                        "severity":           incident["severity"],
                        "risk_score":         incident["risk_score"],
                        "tool":               incident["tool"],
                        "timestamp":          incident["created_at"],
                        "matched_conditions": matched_conds,
                    })

    return {
        "total_events":     total_events,
        "matches_per_rule": matches_per_rule,
        "summary":          f"Replayed {total_events} events against {len(rules)} rules",
        "replayed_at":      datetime.now(UTC).isoformat(),
        "hours_back":       hours,
    }
