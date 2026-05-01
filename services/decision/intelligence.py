from __future__ import annotations

import json
from typing import Any

import structlog
from groq import AsyncGroq

from sdk.common.config import settings
from services.decision.schemas import Decision, DecisionContext, ExecutionAction

logger = structlog.get_logger(__name__)

# Hot-path uses the fastest model — this runs inline in the request lifecycle
# with a 5-second total SLA budget, so latency beats quality here.
_MODEL_FAST = settings.GROQ_MODEL_FAST      # llama-3.1-8b-instant  (~50-100ms)
_MODEL_DEEP = settings.GROQ_MODEL           # llama-3.3-70b-versatile

# Risk threshold above which we invoke the larger model for a second opinion
_DEEP_ANALYSIS_THRESHOLD = 0.75

_SYSTEM_PROMPT = """\
You are an AI security firewall making real-time enforcement decisions for an \
enterprise agent governance platform. Your output directly controls whether an \
AI agent's tool call is blocked, monitored, or allowed.

Rules:
1. Only override the heuristic decision when there is strong signal to do so.
2. Never downgrade a KILL or DENY to ALLOW without clear justification.
3. If the heuristic is sound, confirm it — do not change for the sake of changing.
4. Your recommended_action is the final action sent to the enforcement layer.
5. Respond with ONLY valid JSON — no markdown, no explanation text outside the JSON.\
"""

_USER_TEMPLATE = """\
Analyze this AI agent tool-execution event and return your enforcement verdict.

RISK SIGNALS (0.0 = safe, 1.0 = critical):
  tool              : {tool}
  inference_risk    : {inference_risk:.3f}  (prompt injection / tool guard)
  behavior_risk     : {behavior_risk:.3f}  (velocity, sequences, loops)
  anomaly_score     : {anomaly_score:.3f}
  cost_risk         : {cost_risk:.3f}
  cross_agent_risk  : {cross_agent_risk:.3f}
  composite_risk    : {composite_risk:.3f}

FLAGS:
  behavior : {behavior_flags}
  inference: {inference_flags}

HEURISTIC DECISION: {heuristic_action} (risk={heuristic_risk:.3f}, confidence={heuristic_confidence:.2f})
HEURISTIC REASONS : {heuristic_reasons}

Return exactly this JSON schema:
{{
  "recommended_action": "allow|monitor|throttle|escalate|deny|kill",
  "threat_classification": "PROMPT_INJECTION|DATA_EXFILTRATION|COST_ABUSE|COORDINATED_ATTACK|ANOMALOUS_BEHAVIOR|POLICY_VIOLATION|BENIGN",
  "confidence": <float 0.0-1.0>,
  "narrative": "<one sentence plain-English verdict>"
}}\
"""


class GroqSecurityBrain:
    """
    Inline AI security brain — runs in the hot path with a tight timeout.
    Uses llama-3.1-8b-instant (fast model) for all events, upgrading to the
    deeper model only when composite risk is above _DEEP_ANALYSIS_THRESHOLD.
    """

    def __init__(self, api_key: str) -> None:
        self._client = AsyncGroq(api_key=api_key)

    async def evaluate(self, ctx: DecisionContext, heuristic: Decision) -> Decision:
        """
        Asks Groq to validate or override the heuristic decision.
        Falls back to the heuristic on any error (fail-open for latency safety).
        """
        model = _MODEL_DEEP if heuristic.risk >= _DEEP_ANALYSIS_THRESHOLD else _MODEL_FAST

        user_msg = _USER_TEMPLATE.format(
            tool=ctx.tool,
            inference_risk=getattr(ctx, "inference_risk", 0.0),
            behavior_risk=getattr(ctx, "behavior_risk", 0.0),
            anomaly_score=getattr(ctx, "anomaly_score", 0.0),
            cost_risk=getattr(ctx, "cost_risk", 0.0),
            cross_agent_risk=getattr(ctx, "cross_agent_risk", 0.0),
            composite_risk=heuristic.risk,
            behavior_flags=ctx.behavior_flags or [],
            inference_flags=ctx.inference_flags or [],
            heuristic_action=heuristic.action.value,
            heuristic_risk=heuristic.risk,
            heuristic_confidence=heuristic.confidence,
            heuristic_reasons=heuristic.reasons or [],
        )

        try:
            completion = await self._client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=300,
            )

            result: dict[str, Any] = json.loads(
                completion.choices[0].message.content
            )

            action_str = result.get("recommended_action", heuristic.action.value).lower()
            try:
                final_action = ExecutionAction(action_str)
            except ValueError:
                final_action = heuristic.action

            logger.info(
                "ai_brain_verdict",
                model=model,
                heuristic=heuristic.action.value,
                ai_verdict=final_action.value,
                threat=result.get("threat_classification"),
                ai_confidence=result.get("confidence"),
            )

            return Decision(
                action=final_action,
                risk=heuristic.risk,
                confidence=float(result.get("confidence", heuristic.confidence)),
                reasons=[
                    f"AI ({model}): {result.get('narrative', 'Validated')}",
                    *heuristic.reasons,
                ],
                signals=heuristic.signals,
                metadata={
                    "ai_override": final_action != heuristic.action,
                    "brain_model": model,
                    "threat_classification": result.get("threat_classification"),
                    **heuristic.metadata,
                },
            )

        except Exception as exc:
            logger.error("groq_brain_error", model=model, error=str(exc))
            return heuristic  # fail-open: preserve heuristic on timeout / API error

    async def close(self) -> None:
        await self._client.close()
