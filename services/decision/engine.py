from __future__ import annotations

from datetime import datetime, timezone

import structlog

from sdk.common.invariants import assert_risk_valid, clamp_risk
from services.decision.schemas import Decision, DecisionContext, ExecutionAction

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Weight Table
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, float] = {
    "inference": 0.35,
    "behavior": 0.30,
    "anomaly": 0.15,
    "cost": 0.10,
    "cross_agent": 0.10,
}

# ---------------------------------------------------------------------------
# Threshold Table
# ---------------------------------------------------------------------------

_THRESHOLDS = [
    (0.90, ExecutionAction.KILL),
    (0.70, ExecutionAction.ESCALATE),
    (0.50, ExecutionAction.THROTTLE),
    (0.30, ExecutionAction.MONITOR),
    (0.00, ExecutionAction.ALLOW),
]

# ---------------------------------------------------------------------------

def _classify_risk(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.70:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    if score >= 0.30:
        return "MONITOR"
    return "LOW"


def _action_from_score(score: float) -> ExecutionAction:
    for threshold, action in _THRESHOLDS:
        if score >= threshold:
            return action
    return ExecutionAction.ALLOW


# ---------------------------------------------------------------------------
# Decision Engine
# ---------------------------------------------------------------------------

class DecisionEngine:

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if not (0.999 < total < 1.001):
            raise ValueError(f"Weights must sum to 1.0, got {total:.4f}")

    def evaluate(self, ctx: DecisionContext) -> Decision:

        w = self.weights

        # Step 1: Safe adjustment
        policy_adj = float(ctx.policy_risk_adjustment or 0.0)
        safe_adjustment = max(-0.3, min(0.3, policy_adj))

        # Ensure all risks are floats and non-None
        inf_risk = float(ctx.inference_risk or 0.0)
        beh_risk = float(ctx.behavior_risk or 0.0)
        ano_risk = float(ctx.anomaly_score or 0.0)
        cos_risk = float(ctx.cost_risk or 0.0)
        cro_risk = float(ctx.cross_agent_risk or 0.0)

        raw_score = (
            (inf_risk * w["inference"]) +
            (beh_risk * w["behavior"]) +
            (ano_risk * w["anomaly"]) +
            (cos_risk * w["cost"]) +
            (cro_risk * w["cross_agent"]) +
            safe_adjustment
        )

        signals = {
            "inference": round(inf_risk, 4),
            "behavior": round(beh_risk, 4),
            "anomaly": round(ano_risk, 4),
            "cost": round(cos_risk, 4),
            "cross_agent": round(cro_risk, 4),
            "policy_adjustment": round(policy_adj, 4),
        }

        # Step 2: Boosting
        max_signal = max(signals.values())
        if max_signal >= 0.95:
            raw_score = max(raw_score, 0.95)
        elif max_signal >= 0.80:
            raw_score = max(raw_score, 0.60)

        # Step 3: Policy floor
        if not ctx.policy_allowed:
            raw_score = max(raw_score, 0.70)

        # Step 4: Learning adjustment
        fp_rate = float(ctx.false_positive_rate or 0.0)
        if fp_rate > 0.0:
            discount = min(fp_rate * 0.3, 0.20)
            raw_score = max(0.0, raw_score - discount)

        # Step 5: Clamp
        final_score = clamp_risk(raw_score)

        assert_risk_valid(final_score, context=f"agent={ctx.agent_id} tool={ctx.tool}")

        # Step 6: Action
        action = _action_from_score(final_score)

        # Step 7: Reasons (Ensure they are all strings to avoid join() TypeError)
        raw_reasons = (ctx.behavior_flags or []) + (ctx.inference_flags or [])
        reasons: list[str] = [str(r) for r in raw_reasons if r]

        if not ctx.policy_allowed and ctx.policy_reason:
            reasons.append(f"Policy denied: {ctx.policy_reason}")

        if policy_adj != 0:
            reasons.append(f"Policy risk adjustment applied: {policy_adj:+.2f}")

        if inf_risk > 0.60:
            reasons.append("Prompt injection detected")
        if beh_risk > 0.60:
            reasons.append("Behavioral loop detected")
        if ano_risk > 0.70:
            reasons.append("Behavior drift detected")
        if cos_risk > 0.50:
            reasons.append("Cost spike detected")
        if cro_risk > 0.40:
            reasons.append("Cross-agent anomaly detected")

        risk_level = _classify_risk(final_score)

        logger.info(
            "decision_evaluated",
            agent_id=str(ctx.agent_id),
            tenant_id=str(ctx.tenant_id),
            tool=ctx.tool,
            action=action.value,
            risk_score=final_score,
            risk_level=risk_level,
            signals=signals,
        )

        return Decision(
            action=action,
            risk=final_score,
            confidence=ctx.confidence,
            reasons=reasons,
            signals=signals,
            metadata={
                "risk_level": risk_level,
                "weights": w,
                "components": signals,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )

# ---------------------------------------------------------------------------

decision_engine = DecisionEngine()