from __future__ import annotations

import uuid
from typing import Any

import httpx
import structlog

from sdk.common.config import settings

logger = structlog.get_logger(__name__)

class BehaviorClient:
    """Async HTTP client for the Behavior service."""

    def __init__(self) -> None:
        self._base_url = settings.BEHAVIOR_SERVICE_URL.rstrip("/")
        self._timeout = httpx.Timeout(3.0, connect=1.0)
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def analyze(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        tool: str,
        tokens: int = 0
    ) -> dict[str, Any]:
        """Call Behavior Service /analyze endpoint."""
        url = f"{self._base_url}/analyze"
        client = self._get_client()

        payload = {
            "tenant_id": str(tenant_id),
            "agent_id": str(agent_id),
            "tool": tool,
            "tokens": tokens
        }

        try:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {})
            logger.error("behavior_service_error", status_code=resp.status_code)
        except Exception as e:
            logger.error("behavior_service_unreachable", error=str(e))

        # Fallback: safe defaults if service is down
        return {
            "behavior_risk": 0.0,
            "anomaly_score": 0.0,
            "cross_agent_risk": 0.0,
            "confidence": 0.0,
            "flags": ["behavior_intelligence_unavailable"],
            "metadata": {}
        }

    async def check_behavior(
        self,
        agent_id: uuid.UUID,
        tool_name: str,
        payload_hash: str,
        payload_text: str,
        tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Call Behavior Service /check endpoint."""
        url = f"{self._base_url}/check"
        client = self._get_client()

        payload = {
            "agent_id": str(agent_id),
            "tool_name": tool_name,
            "payload_hash": payload_hash,
            "payload_text": payload_text,
            "tenant_id": str(tenant_id)
        }

        try:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {})
        except Exception as e:
            logger.error("behavior_check_failed", error=str(e))

        return {
            "risk_score_modifier": 0.0,
            "flags": [],
            "history": []
        }

behavior_client = BehaviorClient()
