import asyncio
import os
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration

GATEWAY_URL  = os.getenv("GATEWAY_URL",  "http://localhost:8000")
IDENTITY_URL = os.getenv("IDENTITY_URL", "http://localhost:8002")

ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL",    "admin@acp.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password")
ADMIN_TENANT   = os.getenv("ADMIN_TENANT",   "00000000-0000-0000-0000-000000000001")


async def _admin_token(client: httpx.AsyncClient) -> str:
    """Get a short-lived JWT for the seeded admin user via Identity service."""
    resp = await client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"X-Tenant-ID": ADMIN_TENANT},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    data = resp.json()
    return data.get("data", {}).get("access_token") or data.get("access_token", "")


@pytest.mark.asyncio
async def test_full_security_workflow():
    """
    E2E Full Loop Validation (all traffic via gateway, JWT auth)
    1. Authenticate as admin → get JWT
    2. Register Agent
    3. Add Permission
    4. Provision Agent Credentials
    5. Login as Agent → get agent JWT
    6. Execute Tool via Gateway
    7. Verify Audit Trail
    """
    agent_name = f"e2e-agent-{uuid.uuid4().hex[:8]}"
    secret     = "e2e-secret-12345678-long-enough"
    tenant_id  = ADMIN_TENANT

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Admin JWT
        admin_token = await _admin_token(client)
        auth_headers = {
            "Authorization": f"Bearer {admin_token}",
            "X-Tenant-ID":   tenant_id,
        }

        # 2. Register Agent
        reg_resp = await client.post(
            f"{GATEWAY_URL}/agents",
            json={"name": agent_name, "description": "E2E Test Agent long description here", "owner_id": "admin-1"},
            headers=auth_headers,
        )
        assert reg_resp.status_code in (200, 201), f"Agent create failed: {reg_resp.text}"
        agent_id = reg_resp.json()["data"]["id"]

        # 3. Add Permission
        perm_resp = await client.post(
            f"{GATEWAY_URL}/agents/{agent_id}/permissions",
            json={"tool_name": "system.cleanup", "action": "ALLOW", "granted_by": "admin-1"},
            headers=auth_headers,
        )
        assert perm_resp.status_code in (200, 201), f"Permission add failed: {perm_resp.text}"

        # 4. Provision Agent Credentials
        cred_resp = await client.post(
            f"{GATEWAY_URL}/auth/credentials",
            json={"agent_id": str(agent_id), "secret": secret},
            headers=auth_headers,
        )
        assert cred_resp.status_code in (200, 201), f"Credential provision failed: {cred_resp.text}"

        # 5. Agent Login → JWT
        login_resp = await client.post(
            f"{GATEWAY_URL}/auth/agent/token",
            json={"agent_id": agent_id, "secret": secret},
            headers={"X-Tenant-ID": tenant_id},
        )
        assert login_resp.status_code == 200, f"Agent login failed: {login_resp.text}"
        token_data = login_resp.json()
        agent_token = token_data.get("data", {}).get("access_token") or token_data.get("access_token", "")

        # 6. Execute Tool via Gateway
        agent_headers = {
            "Authorization": f"Bearer {agent_token}",
            "X-Tenant-ID":   tenant_id,
            "X-Agent-ID":    str(agent_id),
        }
        gw_resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers=agent_headers,
            json={"tool": "system.cleanup", "payload": {"path": "/tmp/logs"}},
        )
        assert gw_resp.status_code in (200, 202, 403), \
            f"Unexpected execute status {gw_resp.status_code}: {gw_resp.text}"

        # 7. Verify Audit Log
        await asyncio.sleep(0.5)
        audit_resp = await client.get(
            f"{GATEWAY_URL}/audit/logs",
            params={"agent_id": agent_id},
            headers=auth_headers,
        )
        assert audit_resp.status_code == 200
        logs = audit_resp.json()["data"]["items"]
        assert len(logs) >= 1


@pytest.mark.asyncio
async def test_gateway_unauthorized_access():
    """Security Validation — invalid token must return 401 or 429 (auth failure rate limit)."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={
                "Authorization": "Bearer invalid-token",
                "X-Tenant-ID":   str(uuid.uuid4()),
            },
            json={},
        )
        # 429 is also valid: auth failure rate limit kicks in after repeated failures
        assert resp.status_code in (401, 429), \
            f"Expected 401 or 429, got {resp.status_code}: {resp.text}"
        error_msg = resp.json()["error"]
        assert any(kw in error_msg for kw in ("Invalid", "token", "Authentication", "authentication", "failures")), \
            f"Unexpected error message: {error_msg}"
