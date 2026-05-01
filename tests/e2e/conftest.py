"""
E2E test fixtures — agent auth session that replicates the full
register → provision credentials → login → bearer token handshake.

All fixtures are session-scoped so we pay the network cost once per test run.
"""
from __future__ import annotations

import uuid

import httpx
import pytest
import pytest_asyncio

IDENTITY_URL = "http://localhost:8002"
REGISTRY_URL = "http://localhost:8001"
GATEWAY_URL  = "http://localhost:8000"


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires live stack (skipped when stack is down)")


@pytest.fixture(scope="session", autouse=True)
def require_stack():
    """Skip all e2e tests when the gateway is not reachable."""
    import socket
    try:
        sock = socket.create_connection(("localhost", 8000), timeout=2)
        sock.close()
    except OSError:
        pytest.skip("ACP stack not running — start with: docker compose -f infra/docker-compose.yml up -d")


@pytest_asyncio.fixture(scope="session")
async def http_client():
    """Shared httpx.AsyncClient for the whole test session."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        yield client


@pytest_asyncio.fixture(scope="session")
async def agent_session(http_client: httpx.AsyncClient):
    """
    Full agent auth handshake:
      1. Register agent in registry
      2. Provision credentials in identity service
      3. Issue JWT via identity /auth/token
    Returns dict with keys: agent_id, tenant_id, token, headers
    """
    tenant_id = str(uuid.uuid4())
    secret     = f"e2e-fixture-secret-{uuid.uuid4().hex}"
    headers    = {"X-Tenant-ID": tenant_id}

    # 1. Register
    reg = await http_client.post(
        f"{GATEWAY_URL}/agents",
        json={"name": f"fixture-agent-{uuid.uuid4().hex[:6]}",
              "description": "Session-scoped e2e fixture agent",
              "owner_id": "e2e-fixture"},
        headers=headers,
    )
    reg.raise_for_status()
    agent_id = reg.json()["data"]["id"]

    # 2. Provision credentials
    cred = await http_client.post(
        f"{GATEWAY_URL}/auth/credentials",
        json={"agent_id": agent_id, "secret": secret},
        headers=headers,
    )
    cred.raise_for_status()

    # 3. Issue token
    login = await http_client.post(
        f"{GATEWAY_URL}/auth/agent/token",
        json={"agent_id": agent_id, "secret": secret},
        headers=headers,
    )
    login.raise_for_status()
    res_data = login.json()
    token = res_data.get("data", {}).get("access_token") or res_data.get("access_token", "")

    yield {
        "agent_id":  agent_id,
        "tenant_id": tenant_id,
        "token":     token,
        "headers": {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID":   tenant_id,
        },
    }


@pytest_asyncio.fixture(scope="session")
async def gateway_client():
    """
    httpx.AsyncClient pre-pointed at the gateway.
    Does NOT carry auth — use agent_session fixture headers per-request.
    """
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=10.0) as client:
        yield client
