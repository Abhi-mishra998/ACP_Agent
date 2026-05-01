from __future__ import annotations

import uuid
from typing import Any

import httpx
import structlog

from services.identity.database import settings
from services.identity.exceptions import AgentNotFoundError

# =========================
# REGISTRY CLIENT
# =========================


class RegistryClient:
    """Async HTTP client wrapping the Registry service."""

    def __init__(self) -> None:
        self._base_url = settings.REGISTRY_SERVICE_URL.rstrip("/")
        self._timeout = httpx.Timeout(5.0, connect=2.0)

    def _get_headers(self, tenant_id: uuid.UUID | None = None) -> dict[str, str]:
        """Always include X-Internal-Secret for service mesh auth (P0-4 fix)."""
        headers: dict[str, str] = {"X-Internal-Secret": settings.INTERNAL_SECRET}
        if tenant_id:
            headers["X-Tenant-ID"] = str(tenant_id)
        request_id = structlog.contextvars.get_contextvars().get("request_id")
        if request_id:
            headers["X-Request-ID"] = str(request_id)
        return headers


    async def agent_exists(
        self, agent_id: uuid.UUID, tenant_id: uuid.UUID | None = None
    ) -> bool:
        """Return True if the agent exists and is active in the registry."""
        url = f"{self._base_url}/agents/{agent_id}"
        headers = self._get_headers(tenant_id=tenant_id)
        async with httpx.AsyncClient(timeout=self._timeout, headers=headers) as client:
            try:
                response = await client.get(url)
            except httpx.RequestError:
                # If registry is unreachable, fail closed (deny)
                return False

        if response.status_code == 404:
            return False

        if response.status_code == 200:
            data = response.json()
            # The Registry response structure might have agent data in 'data' field or direct.
            # Looking at previous logs, it returns {'success': True, 'data': {...}}
            agent_data = data.get("data", data)
            from sdk.common.enums import AgentStatus
            return bool(agent_data.get("status") == AgentStatus.ACTIVE.value)

        return False

    async def get_agent(self, agent_id: uuid.UUID, tenant_id: uuid.UUID | None = None) -> dict[str, Any]:
        """Fetch agent metadata; raises AgentNotFoundError if absent."""
        url = f"{self._base_url}/agents/{agent_id}"
        headers = self._get_headers(tenant_id=tenant_id)
        async with httpx.AsyncClient(
            timeout=self._timeout, headers=headers
        ) as client:
            try:
                response = await client.get(url)
            except httpx.RequestError as exc:
                raise AgentNotFoundError() from exc

        if response.status_code != 200:
            import structlog
            structlog.get_logger().error("registry_get_agent_error", status_code=response.status_code, body=response.text)
            raise AgentNotFoundError()

        return dict(response.json())


registry_client = RegistryClient()
