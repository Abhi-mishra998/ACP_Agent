"""
Inference Proxy — ACP Core Security Layer
==========================================
Sits between Auth/Rate-Limit and Policy evaluation.

Components:
    A. InputValidator       — reject oversized / malformed payloads
    B. InjectionDetector    — rule-based prompt injection detection
    C. ToolGuard            — deny tools not in agent's allow-list
    D. RiskScorer           — keyword + length + structure heuristics
    E. TenantIsolationCheck — cross-tenant request blocking
    F. OutputFilter         — redact secrets/tokens from responses

All decisions are logged via structlog.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

_MAX_PAYLOAD_CHARS: int = 5000

# Prompt injection patterns (case-insensitive)
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"delete\s+all\s+data", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(
        r"disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"forget\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|context)",
        re.IGNORECASE,
    ),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\s+", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+)?prompt", re.IGNORECASE),
    re.compile(
        r"bypass\s+(?:all\s+)?(?:security|restrictions?|filters?)", re.IGNORECASE
    ),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(
        r"override\s+(?:all\s+)?(?:safety|security|content)\s+(?:filters?|guidelines?|rules?)",
        re.IGNORECASE,
    ),
]

# Risk-scoring keyword weights (0-100 scale)
_RISK_KEYWORDS: dict[str, float] = {
    "password": 20.0,
    "secret": 20.0,
    "token": 15.0,
    "credential": 20.0,
    "api_key": 20.0,
    "private_key": 25.0,
    "ssh": 15.0,
    "root": 10.0,
    "admin": 10.0,
    "sudo": 15.0,
    "exec": 10.0,
    "eval": 10.0,
    "system": 5.0,
    "drop": 15.0,
    "truncate": 15.0,
    "delete": 10.0,
    "remove": 5.0,
    "format": 5.0,
    "override": 10.0,
    "bypass": 20.0,
    "inject": 20.0,
    "script": 10.0,
    "shell": 15.0,
    "cmd": 10.0,
    "powershell": 15.0,
    "wget": 15.0,
    "curl": 5.0,
    "chmod": 15.0,
    "chown": 15.0,
    "nc ": 20.0,  # netcat
    "base64": 10.0,
}

_RISK_THRESHOLD: float = 0.7

# Output redaction patterns
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Generic secret/key patterns — key=value AND JSON "key": "value" formats
    (
        re.compile(
            r'(?:"(?:secret|password|passwd|pwd)"\s*:\s*"[^"]*")', re.IGNORECASE
        ),
        '"password": "***REDACTED***"',
    ),
    (
        re.compile(
            r'(?:secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\',}]+)["\']?',
            re.IGNORECASE,
        ),
        r"secret=***REDACTED***",
    ),
    # API key patterns — JSON + bare
    (
        re.compile(r'(?:"(?:api[_-]?key|apikey)"\s*:\s*"[^"]*")', re.IGNORECASE),
        '"api_key": "***REDACTED***"',
    ),
    (
        re.compile(
            r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([^\s"\',}]+)["\']?', re.IGNORECASE
        ),
        r"api_key=***REDACTED***",
    ),
    # Private key patterns — JSON + bare
    (
        re.compile(r'(?:"(?:private[_-]?key)"\s*:\s*"[^"]*")', re.IGNORECASE),
        '"private_key": "***REDACTED***"',
    ),
    (
        re.compile(
            r'(?:private[_-]?key)\s*[=:]\s*["\']?([^\s"\',}]+)["\']?', re.IGNORECASE
        ),
        r"private_key=***REDACTED***",
    ),
    # JWT tokens (3-part base64url)
    (
        re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),
        "***JWT_REDACTED***",
    ),
    # AWS-style keys
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***AWS_KEY_REDACTED***"),
    # Generic hex secrets (32+ hex chars)
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "***HEX_SECRET_REDACTED***"),
    # Bearer tokens in strings
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]+", re.IGNORECASE), "Bearer ***REDACTED***"),
    # Authorization headers
    (
        re.compile(r'"Authorization"\s*:\s*"[^"]*"', re.IGNORECASE),
        '"Authorization": "***REDACTED***"',
    ),
    # PEM-encoded private keys
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "***PEM_KEY_REDACTED***",
    ),
]


# ---------------------------------------------------------------------------
# RESULT TYPES
# ---------------------------------------------------------------------------


@dataclass
class ProxyDecision:
    """Result returned by every proxy check."""

    allowed: bool
    reason: str
    status_code: int = 400
    risk_score: float = 0.0
    risk_level: str = "low"
    flags: list[str] = field(default_factory=list)
    prompt_hash: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# A. INPUT VALIDATOR
# ---------------------------------------------------------------------------


class InputValidator:
    """Rejects oversized, non-JSON, or structurally invalid payloads."""

    @staticmethod
    def validate(raw_body: bytes | None, content_type: str | None) -> ProxyDecision:
        if raw_body is None or len(raw_body) == 0:
            # Empty body is valid for GET-style requests
            return ProxyDecision(allowed=True, reason="empty body allowed")

        body_str = raw_body.decode("utf-8", errors="replace")

        # Size check
        if len(body_str) > _MAX_PAYLOAD_CHARS:
            logger.warning(
                "input_validation_rejected",
                reason="oversized_payload",
                size=len(body_str),
                limit=_MAX_PAYLOAD_CHARS,
            )
            return ProxyDecision(
                allowed=False,
                reason=(
                    f"Payload too large: {len(body_str)} chars "
                    f"(limit: {_MAX_PAYLOAD_CHARS})"
                ),
                metadata={"size": len(body_str)},
            )

        # JSON validation only if content-type indicates JSON
        if content_type and "application/json" in content_type:
            try:
                json.loads(body_str)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "input_validation_rejected", reason="malformed_json", error=str(exc)
                )
                return ProxyDecision(
                    allowed=False,
                    reason=f"Malformed JSON: {exc.msg}",
                    metadata={"json_error": str(exc)},
                )

        return ProxyDecision(
            allowed=True, reason="input valid", metadata={"size": len(body_str)}
        )


# ---------------------------------------------------------------------------
# B. INJECTION DETECTOR
# ---------------------------------------------------------------------------


class InjectionDetector:
    """Rule-based prompt injection detection."""

    @staticmethod
    def scan(text: str) -> ProxyDecision:
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                logger.warning(
                    "injection_detected",
                    pattern=pattern.pattern,
                    match=match.group(0)[:80],
                )
                return ProxyDecision(
                    allowed=False,
                    reason=f"Prompt injection detected: '{match.group(0)[:60]}'",
                    status_code=403,
                    flags=["prompt_injection"],
                    risk_score=95.0,
                    risk_level="critical",
                    metadata={"pattern": pattern.pattern, "match": match.group(0)[:80]},
                )
        return ProxyDecision(allowed=True, reason="no injection detected")


# ---------------------------------------------------------------------------
# C. TOOL GUARD
# ---------------------------------------------------------------------------


class ToolGuard:
    """Denies execution of tools not in the agent's allow-list."""

    @staticmethod
    def check(tool_name: str, allowed_tools: list[str] | None) -> ProxyDecision:
        if allowed_tools is None:
            # No restriction list — delegate to OPA
            return ProxyDecision(allowed=True, reason="no tool restriction")

        # Wildcard "*" grants access to all tools (used for ADMIN / management contexts)
        if "*" in allowed_tools:
            return ProxyDecision(allowed=True, reason="wildcard permission granted")

        if tool_name in allowed_tools:
            return ProxyDecision(allowed=True, reason="tool in allow-list")

        logger.warning("tool_guard_denied", tool=tool_name, allowed=allowed_tools)
        return ProxyDecision(
            allowed=False,
            reason=f"Tool '{tool_name}' not in agent's allow-list",
            status_code=403,
            metadata={"tool": tool_name, "allowed_tools": allowed_tools},
        )


# ---------------------------------------------------------------------------
# D. RISK SCORER
# ---------------------------------------------------------------------------


class RiskScorer:
    """
    Compute a [0.0, 1.0] risk score from:
      - Keyword presence and weight
      - Payload length ratio
      - Structural anomalies
    """

    @staticmethod
    def _score_keywords(lower_text: str) -> tuple[float, list[str]]:
        score = 0.0
        triggers = []
        for keyword, weight in _RISK_KEYWORDS.items():
            if keyword in lower_text:
                score += weight
                triggers.append(keyword)
        return score, triggers

    @staticmethod
    def _score_anomalies(text: str) -> tuple[float, list[str]]:
        score = 0.0
        triggers = []

        # 4. Nested encoding patterns
        if re.search(r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", text):
            score += 15.0
            triggers.append("url_encoded_content")

        if re.search(r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}", text):
            score += 15.0
            triggers.append("unicode_escape_sequences")
        return score, triggers

    @staticmethod
    def score(text: str) -> tuple[float, list[str]]:
        lower = text.lower()
        score, triggers = RiskScorer._score_keywords(lower)

        # 2. Length penalty (linear from 2000→5000 chars)
        if len(text) > 2000:
            length_penalty = min((len(text) - 2000) / 30.0, 30.0)
            score += length_penalty
            triggers.append(f"long_payload({len(text)})")

        anomaly_score, anomaly_triggers = RiskScorer._score_anomalies(text)
        score += anomaly_score
        triggers.extend(anomaly_triggers)

        # Cap at 100 and normalize to [0.0, 1.0]
        score = min(score, 100.0) / 100.0
        return score, triggers

    @staticmethod
    def _build_flags(triggers: list[str]) -> list[str]:
        flags: list[str] = []
        if any(
            kw in ["password", "secret", "token", "credential", "private_key"]
            for kw in triggers
        ):
            flags.append("data_exfiltration_risk")
        if any(
            kw in ["drop", "truncate", "delete", "format", "remove"] for kw in triggers
        ):
            flags.append("destructive_action")
        if any(kw in ["bypass", "override", "inject"] for kw in triggers):
            flags.append("security_bypass")
        return flags

    def evaluate(self, text: str) -> ProxyDecision:
        risk_score, triggers = self.score(text)
        flags = self._build_flags(triggers)

        if risk_score >= 0.9:
            risk_level = "critical"
        elif risk_score > _RISK_THRESHOLD:
            risk_level = "high"
        elif risk_score > 0.3:
            risk_level = "medium"
        else:
            risk_level = "low"

        if risk_score > _RISK_THRESHOLD:
            logger.warning(
                "risk_score_exceeded",
                score=round(risk_score, 1),
                threshold=_RISK_THRESHOLD,
                triggers=triggers,
            )
            reason = f"Risk score {risk_score:.0f} exceeds threshold {_RISK_THRESHOLD}"
            return ProxyDecision(
                allowed=False,
                reason=reason,
                status_code=403,
                risk_score=risk_score,
                risk_level=risk_level,
                flags=flags + triggers,
                metadata={"threshold": _RISK_THRESHOLD},
            )

        logger.debug("risk_score_ok", score=round(risk_score, 1), risk_level=risk_level)
        return ProxyDecision(
            allowed=True,
            reason="risk score within threshold",
            risk_score=risk_score,
            risk_level=risk_level,
            flags=flags + triggers,
            metadata={"threshold": _RISK_THRESHOLD},
        )


# ---------------------------------------------------------------------------
# E. TENANT ISOLATION CHECK
# ---------------------------------------------------------------------------


class TenantIsolationChecker:
    """Ensures the request tenant matches the authenticated token tenant."""

    @staticmethod
    def check(
        request_tenant_id: uuid.UUID, token_tenant_id: uuid.UUID
    ) -> ProxyDecision:
        if request_tenant_id != token_tenant_id:
            logger.error(
                "tenant_isolation_violation",
                request_tenant=str(request_tenant_id),
                token_tenant=str(token_tenant_id),
            )
            return ProxyDecision(
                allowed=False,
                reason="Cross-tenant access denied",
                status_code=403,
                metadata={
                    "request_tenant": str(request_tenant_id),
                    "token_tenant": str(token_tenant_id),
                },
            )
        return ProxyDecision(allowed=True, reason="tenant match confirmed")


# ---------------------------------------------------------------------------
# F. OUTPUT FILTER
# ---------------------------------------------------------------------------


class OutputFilter:
    """Redacts secrets, tokens, and credentials from response bodies."""

    @staticmethod
    def redact(body: str) -> str:
        result = body
        for pattern, replacement in _REDACT_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    @staticmethod
    def _detect_high_entropy(text: str) -> bool:
        """Detect if likely secrets (high-entropy strings) escaped regexes."""
        import math

        def shannon_entropy(s: str) -> float:
            p = {}
            lns = float(len(s))
            for c in s:
                p[c] = p.get(c, 0) + 1
            return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

        # Look for 40+ char uninterrupted alphanumeric/base64 strings
        words = re.findall(r"[A-Za-z0-9+/=]{40,}", text)
        return any(shannon_entropy(w) > 4.5 for w in words)

    def filter_response(self, body_bytes: bytes) -> bytes:
        body_str = body_bytes.decode("utf-8", errors="replace")
        redacted = self.redact(body_str)
        if redacted != body_str:
            logger.warning("output_filter_redacted_secrets")

        if self._detect_high_entropy(redacted):
            logger.error("output_filter_high_entropy_detected")
            msg = "High-entropy string detected in output. Possible secret leakage."
            raise ValueError(msg)

        return redacted.encode("utf-8")


# ---------------------------------------------------------------------------
# COMPOSITE INFERENCE PROXY
# ---------------------------------------------------------------------------


class InferenceProxy:
    """
    Orchestrates all inference security checks.
    Call check_input() before dispatch, filter_output() after.
    """

    def __init__(self) -> None:
        self._input_validator = InputValidator()
        self._injection_detector = InjectionDetector()
        self._tool_guard = ToolGuard()
        self._risk_scorer = RiskScorer()
        self._tenant_checker = TenantIsolationChecker()
        self._output_filter = OutputFilter()

    def check_input(
        self,
        *,
        raw_body: bytes | None,
        content_type: str | None,
        tool_name: str,
        allowed_tools: list[str] | None,
        request_tenant_id: uuid.UUID,
        token_tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> ProxyDecision:
        """
        Run all input-side checks in order.
        Returns the first failing decision, or an allow decision.
        """
        # 1. Early checks (Input validation)
        decision = self._run_pre_checks(raw_body, content_type)
        if not decision.allowed:
            return decision

        prompt_hash = hashlib.sha256(raw_body).hexdigest() if raw_body else ""

        # 3. Body-based checks (Injection + Risk)
        body_decision = self._run_body_checks(raw_body)



        if not body_decision.allowed:
            body_decision.prompt_hash = prompt_hash
            return body_decision

        # 4. Request-level checks (Isolation + Tool Guard)
        post_decision = self._run_post_checks(
            tool_name, allowed_tools, request_tenant_id, token_tenant_id
        )
        post_decision.prompt_hash = prompt_hash
        post_decision.risk_score = body_decision.risk_score
        post_decision.risk_level = body_decision.risk_level
        post_decision.flags = body_decision.flags
        post_decision.history = []

        return post_decision

    def _run_pre_checks(
        self, raw_body: bytes | None, content_type: str | None
    ) -> ProxyDecision:
        """Perform initial input validation."""
        return self._input_validator.validate(raw_body, content_type)

    def _run_body_checks(self, raw_body: bytes | None) -> ProxyDecision:
        """Perform text-based analysis checks (Injection, Risk)."""
        if not raw_body:
            return ProxyDecision(allowed=True, reason="no body to scan")

        body_text = raw_body.decode("utf-8", errors="replace")

        # Injection detection
        inj_decision = self._injection_detector.scan(body_text)
        if not inj_decision.allowed:
            return inj_decision

        # Risk scoring
        return self._risk_scorer.evaluate(body_text)

    def _run_post_checks(
        self,
        tool: str,
        allowed: list[str] | None,
        req_tenant: uuid.UUID,
        tok_tenant: uuid.UUID,
    ) -> ProxyDecision:
        """Perform tenant isolation and tool restriction checks."""
        # Tenant isolation
        iso_decision = self._tenant_checker.check(req_tenant, tok_tenant)
        if not iso_decision.allowed:
            return iso_decision

        # Tool restriction
        return self._tool_guard.check(tool, allowed)

    def filter_output(self, body_bytes: bytes) -> bytes:
        """F. Filter response body to remove secrets."""
        return self._output_filter.filter_response(body_bytes)


# Module-level singleton
inference_proxy = InferenceProxy()
