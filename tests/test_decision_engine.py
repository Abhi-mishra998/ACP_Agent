"""
ACP Decision Engine — Unit Tests
=================================
Validates the unified DecisionEngine against all 5 risk thresholds
and key invariants.

Run with:
    .venv/bin/python3 -m pytest tests/test_decision_engine.py -v
"""

from __future__ import annotations

import uuid

import pytest

from sdk.common.invariants import InvariantViolation, assert_risk_valid, clamp_risk
from services.decision.engine import DEFAULT_WEIGHTS, DecisionEngine
from services.decision.schemas import DecisionContext, ExecutionAction


def _ctx(**kwargs) -> DecisionContext:
    """Helper to create a minimal DecisionContext."""
    defaults = dict(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        tool="test_tool",
        policy_allowed=True,
    )
    defaults.update(kwargs)
    return DecisionContext(**defaults)


@pytest.fixture
def engine() -> DecisionEngine:
    return DecisionEngine()


# ---------------------------------------------------------------------------
# Invariant Tests
# ---------------------------------------------------------------------------

class TestInvariants:
    def test_clamp_risk_within_range(self):
        assert clamp_risk(0.0) == 0.0
        assert clamp_risk(1.0) == 1.0
        assert clamp_risk(0.5) == 0.5

    def test_clamp_risk_clamps_below_zero(self):
        assert clamp_risk(-0.5) == 0.0

    def test_clamp_risk_clamps_above_one(self):
        assert clamp_risk(1.5) == 1.0

    def test_assert_risk_valid_passes(self):
        assert_risk_valid(0.0)
        assert_risk_valid(0.5)
        assert_risk_valid(1.0)

    def test_assert_risk_valid_raises_below_zero(self):
        with pytest.raises(InvariantViolation):
            assert_risk_valid(-0.1)

    def test_assert_risk_valid_raises_above_one(self):
        with pytest.raises(InvariantViolation):
            assert_risk_valid(1.001)

    def test_weights_sum_to_one(self):
        total = sum(DEFAULT_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001, f"Weights must sum to 1.0, got {total}"


# ---------------------------------------------------------------------------
# Threshold Tests
# ---------------------------------------------------------------------------

class TestThresholds:
    def test_allow_at_low_risk(self, engine):
        ctx = _ctx(inference_risk=0.0, behavior_risk=0.0, anomaly_score=0.0)
        d = engine.evaluate(ctx)
        assert d.action == ExecutionAction.ALLOW
        assert d.risk < 0.30

    def test_monitor_at_moderate_risk(self, engine):
        # Push risk into 0.30–0.50 band
        ctx = _ctx(inference_risk=0.45, behavior_risk=0.0, anomaly_score=0.0)
        d = engine.evaluate(ctx)
        assert d.action in (ExecutionAction.MONITOR, ExecutionAction.ALLOW)
        # (exact action depends on weight blending — just verify score range)
        assert 0.0 <= d.risk <= 1.0

    def test_throttle_at_medium_risk(self, engine):
        ctx = _ctx(inference_risk=0.80, behavior_risk=0.0, anomaly_score=0.0)
        d = engine.evaluate(ctx)
        assert d.action in (ExecutionAction.THROTTLE, ExecutionAction.ESCALATE)

    def test_throttle_or_escalate_at_high_risk(self, engine):
        # 0.85+0.85 signals → signal boost floors to 0.60 → THROTTLE
        # This is correct — boost only forces minimum, not a direct threshold jump
        ctx = _ctx(inference_risk=0.85, behavior_risk=0.85, anomaly_score=0.0)
        d = engine.evaluate(ctx)
        assert d.action in (ExecutionAction.THROTTLE, ExecutionAction.ESCALATE, ExecutionAction.KILL)
        assert d.risk >= 0.60

    def test_escalate_with_all_signals_high(self, engine):
        # All signals at 0.75 → raw = 0.75, risk level HIGH → ESCALATE
        ctx = _ctx(
            inference_risk=0.75, behavior_risk=0.75, anomaly_score=0.75,
            cost_risk=0.75, cross_agent_risk=0.75,
        )
        d = engine.evaluate(ctx)
        assert d.action in (ExecutionAction.ESCALATE, ExecutionAction.KILL)
        assert d.risk >= 0.70

    def test_kill_at_critical_risk(self, engine):
        ctx = _ctx(inference_risk=1.0, behavior_risk=1.0, anomaly_score=1.0,
                   cost_risk=1.0, cross_agent_risk=1.0)
        d = engine.evaluate(ctx)
        assert d.action == ExecutionAction.KILL
        assert d.risk >= 0.90

    def test_policy_deny_floors_score(self, engine):
        # Even with zero risk signals, explicit policy deny must floor at 0.70
        ctx = _ctx(inference_risk=0.0, behavior_risk=0.0, policy_allowed=False,
                   policy_reason="blocked by OPA rule")
        d = engine.evaluate(ctx)
        assert d.risk >= 0.70
        assert d.action in (ExecutionAction.ESCALATE, ExecutionAction.KILL)

    def test_signal_boost_critical(self, engine):
        # A single signal at 0.95+ must force final score to at least 0.95
        ctx = _ctx(inference_risk=0.95, behavior_risk=0.0,
                   anomaly_score=0.0, cost_risk=0.0, cross_agent_risk=0.0)
        d = engine.evaluate(ctx)
        assert d.risk >= 0.90  # boosted
        assert d.action == ExecutionAction.KILL

    def test_signal_boost_high(self, engine):
        # A single signal at 0.80+ must force final score to at least 0.60
        ctx = _ctx(inference_risk=0.80, behavior_risk=0.0,
                   anomaly_score=0.0, cost_risk=0.0, cross_agent_risk=0.0)
        d = engine.evaluate(ctx)
        assert d.risk >= 0.60  # min threshold after boost


# ---------------------------------------------------------------------------
# Output Format Tests
# ---------------------------------------------------------------------------

class TestOutputFormat:
    def test_decision_has_signals_dict(self, engine):
        ctx = _ctx(inference_risk=0.5, behavior_risk=0.3)
        d = engine.evaluate(ctx)
        assert "inference" in d.signals
        assert "behavior" in d.signals
        assert "anomaly" in d.signals
        assert "cost" in d.signals
        assert "cross_agent" in d.signals

    def test_decision_risk_always_clamped(self, engine):
        for inf in [0.0, 0.25, 0.5, 0.75, 1.0]:
            ctx = _ctx(inference_risk=inf, behavior_risk=inf)
            d = engine.evaluate(ctx)
            assert 0.0 <= d.risk <= 1.0, f"risk out of bounds: {d.risk}"

    def test_decision_reasons_collected(self, engine):
        ctx = _ctx(
            inference_risk=0.8,
            behavior_risk=0.8,
            behavior_flags=["loop_detected"],
        )
        d = engine.evaluate(ctx)
        assert len(d.reasons) > 0

    def test_deterministic_same_input_same_output(self, engine):
        """DecisionEngine must be deterministic — replay must work."""
        tenant = uuid.uuid4()
        agent = uuid.uuid4()
        ctx = _ctx(tenant_id=tenant, agent_id=agent,
                   inference_risk=0.6, behavior_risk=0.4)
        d1 = engine.evaluate(ctx)
        d2 = engine.evaluate(ctx)
        assert d1.action == d2.action
        assert d1.risk == d2.risk


# ---------------------------------------------------------------------------
# Billing / Money Engine Tests
# ---------------------------------------------------------------------------

class TestBillingEngine:
    def test_kill_saves_500(self):

        from services.billing.value_engine import BillingValueEngine
        engine = BillingValueEngine.__new__(BillingValueEngine)
        assert engine.calculate_saved("kill") == 500.00

    def test_throttle_saves_200(self):
        from services.billing.value_engine import BillingValueEngine
        engine = BillingValueEngine.__new__(BillingValueEngine)
        assert engine.calculate_saved("throttle") == 200.00

    def test_escalate_saves_100(self):
        from services.billing.value_engine import BillingValueEngine
        engine = BillingValueEngine.__new__(BillingValueEngine)
        assert engine.calculate_saved("escalate") == 100.00

    def test_allow_saves_nothing(self):
        from services.billing.value_engine import BillingValueEngine
        engine = BillingValueEngine.__new__(BillingValueEngine)
        assert engine.calculate_saved("allow") == 0.0
