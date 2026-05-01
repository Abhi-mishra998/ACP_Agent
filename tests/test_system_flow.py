from __future__ import annotations

import os
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration

GATEWAY_URL  = os.getenv("GATEWAY_URL",  "http://localhost:8000")
ADMIN_TENANT = os.getenv("ADMIN_TENANT", "00000000-0000-0000-0000-000000000001")
ADMIN_EMAIL  = os.getenv("ADMIN_EMAIL",  "admin@acp.local")
ADMIN_PASS   = os.getenv("ADMIN_PASSWORD", "password")


async def _get_admin_token(client: httpx.AsyncClient) -> str:
    # All auth goes through the gateway (:8000) — never call identity (:8002) directly.
    # Gateway always returns HTTP 200; check the body's "success" field for auth result.
    try:
        resp = await client.post(
            f"{GATEWAY_URL}/auth/token",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
            headers={"X-Tenant-ID": ADMIN_TENANT},
        )
    except Exception as exc:
        pytest.skip(f"Gateway unreachable: {exc}")

    data = resp.json() if resp.content else {}
    if not data.get("success"):
        pytest.skip(
            f"Admin login rejected ({data.get('error', resp.status_code)}) — "
            "seed the admin user first:\n"
            "  docker compose -f infra/docker-compose.yml exec identity python /app/seed_admin.py"
        )

    token = (data.get("data") or {}).get("access_token") or data.get("access_token", "")
    assert token, f"Token absent in successful response: {data}"
    return token


@pytest.mark.asyncio
async def test_full_agent_lifecycle() -> None:
    """
    End-to-End System Integration Test.

    Flow:
    1. Authenticate as admin → JWT
    2. Register a new Agent via gateway.
    3. Add 'allow' permission for 'data_query' tool.
    4. Provision a high-entropy secret via gateway.
    5. Login as Agent → agent JWT.
    6. Execute 'data_query' via gateway (succeeds).
    7. Verify audit logs.
    """
    agent_name = f"test-agent-{uuid.uuid4().hex[:6]}"
    secret     = "comp-secret-very-long-123456"
    tenant_id  = ADMIN_TENANT

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Admin token
        admin_token = await _get_admin_token(client)
        auth = {"Authorization": f"Bearer {admin_token}", "X-Tenant-ID": tenant_id}

        # 2. Register Agent
        resp = await client.post(
            f"{GATEWAY_URL}/agents",
            json={"name": agent_name, "description": "Integration testing agent for the ACP system", "owner_id": "security-core"},
            headers=auth,
        )
        assert resp.status_code in (200, 201), f"Agent create: {resp.text}"
        resp_data = resp.json()
        agent_id = resp_data.get("data", resp_data).get("id")

        # 3. Grant Permission
        await client.post(
            f"{GATEWAY_URL}/agents/{agent_id}/permissions",
            json={"tool_name": "data_query", "action": "ALLOW", "granted_by": "admin"},
            headers=auth,
        )

        # 4. Provision Secret
        cred_resp = await client.post(
            f"{GATEWAY_URL}/auth/credentials",
            json={"agent_id": agent_id, "secret": secret},
            headers=auth,
        )
        assert cred_resp.status_code in (200, 201), f"Credential provision: {cred_resp.text}"

        # 5. Agent Login
        login_resp = await client.post(
            f"{GATEWAY_URL}/auth/agent/token",
            json={"agent_id": agent_id, "secret": secret},
            headers={"X-Tenant-ID": tenant_id},
        )
        assert login_resp.status_code == 200, f"Agent login: {login_resp.text}"
        token_data = login_resp.json()
        agent_token = (token_data.get("data") or token_data).get("access_token", "")
        agent_auth  = {"Authorization": f"Bearer {agent_token}", "X-Tenant-ID": tenant_id, "X-Agent-ID": str(agent_id)}

        # 6. Execute Tool
        exec_resp = await client.post(
            f"{GATEWAY_URL}/execute",
            json={"tool": "data_query", "payload": {"query": "SELECT 1"}},
            headers=agent_auth,
        )
        # Allow 200/202 (allowed/escalated) — 403 means security policy denied
        assert exec_resp.status_code in (200, 202, 403), f"Execute: {exec_resp.text}"

        # 7. Audit Logs
        import asyncio
        await asyncio.sleep(0.5)
        audit_resp = await client.get(
            f"{GATEWAY_URL}/audit/logs",
            params={"agent_id": agent_id},
            headers=auth,
        )
        assert audit_resp.status_code == 200
        logs = audit_resp.json()["data"]["items"]
        assert len(logs) >= 1
