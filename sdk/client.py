from __future__ import annotations

import httpx
import uuid
from typing import Any, Dict, Optional

from sdk.common.exceptions import (
    ACPAuthError,
    ACPConnectionError,
    ACPPolicyDeniedError,
    ACPError,
)


class ACPClient:
    """
    Official SDK Client for the Agent Control Plane.

    Handles authentication, tool execution proxying, and security enforcement
    on behalf of agents.

    Args:
        agent_id:     UUID string of the registerd agent.
        secret:       Agent secret provisioned via /auth/credentials.
        gateway_url:  ACP Gateway base URL.
        identity_url: ACP Identity service base URL.
        org_id:       Organisation UUID. When supplied it is sent as X-Org-ID on
                      every request and validated against the token's org_id claim.
                      Defaults to tenant_id when omitted (backwards-compatible).
        timeout:      HTTP timeout in seconds.
    """

    def __init__(
        self,
        agent_id: str,
        secret: str,
        gateway_url: str,
        identity_url: str,
        org_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.agent_id    = agent_id
        self.secret      = secret
        self.gateway_url = gateway_url.rstrip("/")
        self.identity_url = identity_url.rstrip("/")
        self.org_id      = org_id
        self.timeout     = timeout

        self.token:     Optional[str] = None
        self.tenant_id: Optional[str] = None
        self._http_client = httpx.AsyncClient(timeout=timeout)

    async def authenticate(self, tenant_id: str) -> None:
        """Authenticate with the Identity service to obtain a JWT."""
        self.tenant_id = tenant_id
        url = f"{self.gateway_url}/auth/agent/token"

        try:
            resp = await self._http_client.post(
                url,
                json={"agent_id": self.agent_id, "secret": self.secret},
                headers=self._base_headers(),
            )

            if resp.status_code == 401:
                raise ACPAuthError("Invalid agent credentials or inactive status")

            resp.raise_for_status()
            token_data = resp.json().get("data", resp.json())
            self.token = token_data.get("access_token")

            if not self.token:
                raise ACPAuthError("Identity service failed to return an access token")

        except httpx.RequestError as exc:
            raise ACPConnectionError(f"Failed to connect to identity service: {exc}")

    async def execute_tool(
        self,
        tool_name: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a tool via the ACP Gateway.
        Enforces Rule 1 (No tool executes without policy) and Rule 2 (Every action audited).

        Raises ACPPolicyDeniedError on 403.
        Does NOT retry 429 responses — callers must back off and retry themselves.
        """
        if not self.token:
            raise ACPAuthError("Not authenticated. Call authenticate() first.")

        url   = f"{self.gateway_url}/execute"
        i_key = idempotency_key or f"ik_{uuid.uuid4().hex}"

        headers = {
            **self._base_headers(),
            "Authorization":    f"Bearer {self.token}",
            "X-Agent-ID":       str(self.agent_id),
            "X-Idempotency-Key": i_key,
            "X-ACP-Tool":       tool_name,
            "Content-Type":     "application/json",
        }

        try:
            resp = await self._http_client.post(
                url,
                json={"tool": tool_name, "payload": payload},
                headers=headers,
            )

            if resp.status_code == 403:
                error_data = resp.json()
                reason = error_data.get("detail", error_data.get("error", "Policy enforcement denied execution"))
                raise ACPPolicyDeniedError(reason)

            if resp.status_code == 429:
                # Rate limit exceeded — do NOT retry; propagate to caller
                raise ACPError(f"Rate limit exceeded (429): {resp.text}")

            resp.raise_for_status()
            return resp.json()

        except httpx.RequestError as exc:
            raise ACPConnectionError(f"Failed to connect to gateway: {exc}")
        except Exception as exc:
            if isinstance(exc, (ACPPolicyDeniedError, ACPConnectionError, ACPAuthError, ACPError)):
                raise
            raise ACPError(f"An unexpected error occurred during tool execution: {exc}")

    def _base_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"X-Tenant-ID": str(self.tenant_id or "")}
        if self.org_id:
            headers["X-Org-ID"] = self.org_id
        return headers

    async def close(self) -> None:
        await self._http_client.aclose()

    async def __aenter__(self) -> ACPClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
