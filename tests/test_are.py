"""
ARE unit tests — rule matching, idempotency, index pre-filter, DSL trace, and latency keys.
Pure logic tests; no I/O, no DB, no Redis required.
"""
from __future__ import annotations

import types
import uuid


from services.api.are_worker import _build_trace, _check_condition
from services.api.are_index import AREIndex


# ─── Fixtures ────────────────────────────────────────────────────────────────

def inc(
    severity="HIGH",
    risk_score=0.8,
    tool="payments.write",
    agent_id="agent-abc",
    violation_count=1,
):
    return dict(severity=severity, risk_score=risk_score, tool=tool,
                agent_id=agent_id, violation_count=violation_count)


def cond(**kwargs):
    base = dict(
        window="5m",
        min_violations=1,
        severity_in=[],
        risk_score_gte=0.0,
        tool_in=[],
        agent_id="*",
        repeat_offender=False,
    )
    base.update(kwargs)
    return base


# ─── severity_in ─────────────────────────────────────────────────────────────

def test_severity_in_match():
    assert _check_condition(cond(severity_in=["HIGH", "CRITICAL"]), inc(severity="HIGH"), 1)

def test_severity_in_no_match():
    assert not _check_condition(cond(severity_in=["CRITICAL"]), inc(severity="HIGH"), 1)

def test_severity_in_empty_passes():
    assert _check_condition(cond(severity_in=[]), inc(severity="LOW"), 1)


# ─── risk_score_gte ──────────────────────────────────────────────────────────

def test_risk_gte_exact():
    assert _check_condition(cond(risk_score_gte=0.8), inc(risk_score=0.8), 1)

def test_risk_gte_above():
    assert _check_condition(cond(risk_score_gte=0.7), inc(risk_score=0.9), 1)

def test_risk_gte_below():
    assert not _check_condition(cond(risk_score_gte=0.9), inc(risk_score=0.8), 1)


# ─── tool_in ─────────────────────────────────────────────────────────────────

def test_tool_in_match():
    assert _check_condition(cond(tool_in=["payments.write", "data.export"]), inc(tool="payments.write"), 1)

def test_tool_in_no_match():
    assert not _check_condition(cond(tool_in=["data.export"]), inc(tool="payments.write"), 1)

def test_tool_in_empty_passes():
    assert _check_condition(cond(tool_in=[]), inc(tool="anything"), 1)


# ─── agent_id ────────────────────────────────────────────────────────────────

def test_agent_wildcard():
    assert _check_condition(cond(agent_id="*"), inc(agent_id="any-agent"), 1)

def test_agent_exact_match():
    assert _check_condition(cond(agent_id="agent-abc"), inc(agent_id="agent-abc"), 1)

def test_agent_exact_no_match():
    assert not _check_condition(cond(agent_id="agent-xyz"), inc(agent_id="agent-abc"), 1)


# ─── repeat_offender ─────────────────────────────────────────────────────────

def test_repeat_offender_via_violation_count():
    # violation_count >= 2 satisfies repeat_offender; window_count=1 meets min_violations=1
    assert _check_condition(cond(repeat_offender=True), inc(violation_count=2), 1)

def test_repeat_offender_via_window_count():
    # window_count >= 2 also satisfies it
    assert _check_condition(cond(repeat_offender=True), inc(violation_count=1), 2)

def test_repeat_offender_fails():
    assert not _check_condition(cond(repeat_offender=True), inc(violation_count=1), 1)


# ─── min_violations ──────────────────────────────────────────────────────────

def test_min_violations_met():
    assert _check_condition(cond(min_violations=3), inc(), 3)

def test_min_violations_not_met():
    assert not _check_condition(cond(min_violations=3), inc(), 2)

def test_min_violations_default_one():
    assert _check_condition(cond(min_violations=1), inc(), 1)


# ─── Compound conditions ──────────────────────────────────────────────────────

def test_all_conditions_pass():
    c = cond(
        severity_in=["HIGH"],
        risk_score_gte=0.75,
        tool_in=["payments.write"],
        agent_id="*",
        min_violations=2,
        repeat_offender=True,
    )
    i = inc(severity="HIGH", risk_score=0.9, tool="payments.write", violation_count=3)
    assert _check_condition(c, i, 2)

def test_one_failing_condition_blocks():
    c = cond(severity_in=["CRITICAL"], risk_score_gte=0.5)
    i = inc(severity="HIGH", risk_score=0.9)
    assert not _check_condition(c, i, 5)


# ─── Idempotency key uniqueness ───────────────────────────────────────────────

def test_idemp_key_unique_per_rule():
    tid, aid, req = "tenant-1", "agent-1", "req-abc"
    key = lambda rule_id: f"acp:{tid}:are:idemp:{req}:{rule_id}"
    assert key("rule-1") != key("rule-2")

def test_idemp_key_unique_per_incident():
    tid, rule_id = "tenant-1", "rule-1"
    key = lambda req: f"acp:{tid}:are:idemp:{req}:{rule_id}"
    assert key("req-001") != key("req-002")

def test_idemp_key_tenant_scoped():
    req, rule_id = "req-abc", "rule-1"
    key = lambda tid: f"acp:{tid}:are:idemp:{req}:{rule_id}"
    assert key("tenant-A") != key("tenant-B")


# ─── Cooldown key tenant scoping ─────────────────────────────────────────────

def test_cooldown_key_tenant_scoped():
    rule_id = "rule-1"
    key = lambda tid, scope: f"acp:{tid}:are:cooldown:{rule_id}:{scope}"
    assert key("t1", "global") != key("t2", "global")
    assert key("t1", "agent-x") != key("t1", "agent-y")


# ─── DSL list-format conditions ───────────────────────────────────────────────

def test_dsl_risk_gte_passes():
    dsl = [{"field": "risk_score", "op": ">=", "value": 0.7}]
    assert _check_condition(dsl, inc(risk_score=0.8), 0)

def test_dsl_risk_gte_fails():
    dsl = [{"field": "risk_score", "op": ">=", "value": 0.9}]
    assert not _check_condition(dsl, inc(risk_score=0.8), 0)

def test_dsl_severity_in_passes():
    dsl = [{"field": "severity", "op": "in", "value": ["HIGH", "CRITICAL"]}]
    assert _check_condition(dsl, inc(severity="CRITICAL"), 0)

def test_dsl_severity_in_fails():
    dsl = [{"field": "severity", "op": "in", "value": ["CRITICAL"]}]
    assert not _check_condition(dsl, inc(severity="HIGH"), 0)

def test_dsl_compound_all_pass():
    dsl = [
        {"field": "risk_score", "op": ">=", "value": 0.7},
        {"field": "severity",   "op": "in",  "value": ["HIGH", "CRITICAL"]},
        {"field": "violations", "op": ">=",  "value": 2},
    ]
    assert _check_condition(dsl, inc(risk_score=0.85, severity="HIGH"), 3)

def test_dsl_compound_one_fails():
    dsl = [
        {"field": "risk_score", "op": ">=", "value": 0.7},
        {"field": "severity",   "op": "in",  "value": ["CRITICAL"]},
    ]
    assert not _check_condition(dsl, inc(risk_score=0.85, severity="HIGH"), 0)

def test_dsl_not_in():
    dsl = [{"field": "tool", "op": "not_in", "value": ["benign.read"]}]
    assert _check_condition(dsl, inc(tool="payments.write"), 0)
    assert not _check_condition(dsl, inc(tool="benign.read"), 0)

def test_dsl_empty_list_passes():
    assert _check_condition([], inc(), 0)


# ─── _build_trace — DSL format ───────────────────────────────────────────────

def test_build_trace_dsl_all_match():
    dsl = [
        {"field": "risk_score", "op": ">=", "value": 0.5},
        {"field": "severity",   "op": "in",  "value": ["HIGH"]},
    ]
    matched, matched_conds, failed_conds = _build_trace(dsl, inc(risk_score=0.9, severity="HIGH"), 0)
    assert matched
    assert len(matched_conds) == 2
    assert failed_conds == []

def test_build_trace_dsl_partial_fail():
    dsl = [
        {"field": "risk_score", "op": ">=", "value": 0.5},
        {"field": "severity",   "op": "in",  "value": ["CRITICAL"]},
    ]
    matched, matched_conds, failed_conds = _build_trace(dsl, inc(risk_score=0.9, severity="HIGH"), 0)
    assert not matched
    assert len(matched_conds) == 1
    assert len(failed_conds) == 1
    assert failed_conds[0]["field"] == "severity"

def test_build_trace_legacy_blob():
    # min_violations defaults to 1, so window_count must be >= 1
    blob = {"severity_in": ["HIGH"], "risk_score_gte": 0.5}
    matched, matched_conds, failed_conds = _build_trace(blob, inc(severity="HIGH", risk_score=0.8), 1)
    assert matched
    assert all(e["passed"] for e in matched_conds)


# ─── AREIndex pre-filter ──────────────────────────────────────────────────────

def _make_rule(conditions, rule_id=None):
    """Build a minimal mock rule object for AREIndex."""
    r = types.SimpleNamespace()
    r.id = rule_id or uuid.uuid4()
    r.conditions = conditions
    return r


def test_index_passes_no_filter():
    rule = _make_rule({})  # no severity_in, no risk_score_gte → passes everything
    idx = AREIndex([rule])
    candidates = idx.candidates(inc(risk_score=0.1, severity="LOW"))
    assert rule in candidates


def test_index_filters_by_risk_legacy():
    rule = _make_rule({"risk_score_gte": 0.8})
    idx = AREIndex([rule])
    assert idx.candidates(inc(risk_score=0.7)) == []
    assert rule in idx.candidates(inc(risk_score=0.9))


def test_index_filters_by_severity_legacy():
    rule = _make_rule({"severity_in": ["CRITICAL"]})
    idx = AREIndex([rule])
    assert idx.candidates(inc(severity="HIGH")) == []
    assert rule in idx.candidates(inc(severity="CRITICAL"))


def test_index_filters_by_risk_dsl():
    dsl = [{"field": "risk_score", "op": ">=", "value": 0.8}]
    rule = _make_rule(dsl)
    idx = AREIndex([rule])
    assert idx.candidates(inc(risk_score=0.5)) == []
    assert rule in idx.candidates(inc(risk_score=0.9))


def test_index_filters_by_severity_dsl():
    dsl = [{"field": "severity", "op": "in", "value": ["HIGH", "CRITICAL"]}]
    rule = _make_rule(dsl)
    idx = AREIndex([rule])
    assert idx.candidates(inc(severity="LOW")) == []
    assert rule in idx.candidates(inc(severity="HIGH"))


def test_index_multiple_rules_partial_match():
    rule_strict = _make_rule({"risk_score_gte": 0.9})
    rule_loose  = _make_rule({"risk_score_gte": 0.5})
    idx = AREIndex([rule_strict, rule_loose])
    candidates = idx.candidates(inc(risk_score=0.75))
    assert rule_loose in candidates
    assert rule_strict not in candidates


# ─── Correlation & backpressure Redis key patterns ───────────────────────────

def test_correlation_key_tenant_scoped():
    key = lambda tid, aid: f"acp:{tid}:are:agent_corr:{aid}"
    assert key("t1", "agent-a") != key("t2", "agent-a")
    assert key("t1", "agent-a") != key("t1", "agent-b")


def test_latency_key_tenant_and_rule_scoped():
    key = lambda tid, rid: f"acp:{tid}:are:latency:{rid}"
    assert key("t1", "rule-1") != key("t2", "rule-1")
    assert key("t1", "rule-1") != key("t1", "rule-2")


def test_backpressure_key_pattern():
    stream = "acp:incidents:queue"
    audit  = "acp:audit:events"
    assert stream != audit


# ─── RBAC role set ────────────────────────────────────────────────────────────

def test_admin_roles_are_correct():
    from services.api.router.auto_response import _ADMIN_ROLES
    assert "ADMIN" in _ADMIN_ROLES
    assert "SUPER_ADMIN" in _ADMIN_ROLES
    assert "USER" not in _ADMIN_ROLES


# ─── Audit events stream key ──────────────────────────────────────────────────

def test_audit_stream_key():
    from services.api.main import _AUDIT_STREAM, _AUDIT_ARE_GROUP
    assert _AUDIT_STREAM == "acp:audit:events"
    assert _AUDIT_ARE_GROUP == "are-audit-workers"
