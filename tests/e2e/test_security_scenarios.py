import os
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration

GATEWAY_URL  = os.getenv("GATEWAY_URL",  "http://localhost:8000")
IDENTITY_URL = os.getenv("IDENTITY_URL", "http://localhost:8002")
ADMIN_TENANT = os.getenv("ADMIN_TENANT", "00000000-0000-0000-0000-000000000001")
ADMIN_EMAIL  = os.getenv("ADMIN_EMAIL",  "admin@acp.local")
ADMIN_PASS   = os.getenv("ADMIN_PASSWORD", "password")


async def _admin_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        headers={"X-Tenant-ID": ADMIN_TENANT},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    data = resp.json()
    return data.get("data", {}).get("access_token") or data.get("access_token", "")


async def _agent_login(client: httpx.AsyncClient, agent_id: str, secret: str, tenant_id: str) -> str:
    """Get a fresh agent token (fresh JTI) for each test step."""
    resp = await client.post(
        f"{GATEWAY_URL}/auth/agent/token",
        json={"agent_id": agent_id, "secret": secret},
        headers={"X-Tenant-ID": tenant_id},
    )
    assert resp.status_code == 200, f"Agent login failed: {resp.text}"
    data = resp.json()
    return data.get("data", {}).get("access_token") or data.get("access_token", "")


@pytest.mark.asyncio
async def test_security_scenarios():
    """
    Detailed Security Validations
    1. Missing token
    2. Invalid token
    3. Cross-Tenant access (token tenant ≠ X-Tenant-ID header)
    4. Tool not permitted (fresh JTI to avoid replay detection)
    5. Permission scoping (allowed tool vs denied tool)
    """
    tenant_id = ADMIN_TENANT
    secret_a = "secret-a-12345678"
    secret_c = "secret-c-12345678"

    async with httpx.AsyncClient(timeout=30.0) as client:
        # --- Authenticate as admin ---
        admin_token = await _admin_token(client)
        admin_headers = {
            "Authorization": f"Bearer {admin_token}",
            "X-Tenant-ID": tenant_id,
        }

        # --- Setup: Create Agent A ---
        reg_a = await client.post(
            f"{GATEWAY_URL}/agents",
            json={"name": f"sec-agent-a-{uuid.uuid4().hex[:6]}", "description": "Security test agent A", "owner_id": "test"},
            headers=admin_headers,
        )
        assert reg_a.status_code in (200, 201), f"Agent A create failed: {reg_a.text}"
        agent_a_id = reg_a.json()["data"]["id"]

        await client.post(
            f"{GATEWAY_URL}/auth/credentials",
            json={"agent_id": agent_a_id, "secret": secret_a},
            headers=admin_headers,
        )

        # 1. Missing token -> 401
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={"X-Tenant-ID": tenant_id, "X-Agent-ID": agent_a_id},
            json={"tool": "any.tool", "payload": {}},
        )
        assert resp.status_code == 401, f"Expected 401 for missing token, got {resp.status_code}: {resp.text}"
        err = resp.json()["error"]
        assert any(kw in err for kw in ("Missing", "Authentication required", "Tenant ID required")), \
            f"Unexpected 401 error: {err}"

        # 2. Invalid token -> 401 (or 429 if auth failure rate limit exceeded from prior runs)
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={"Authorization": "Bearer invalid-token", "X-Tenant-ID": tenant_id, "X-Agent-ID": agent_a_id},
            json={"tool": "any.tool", "payload": {}},
        )
        assert resp.status_code in (401, 429), f"Expected 401/429 for invalid token, got {resp.status_code}: {resp.text}"

        # 3. Cross-Tenant access — agent A token with a different tenant header -> 403
        # Fresh login each time to get distinct JTI (avoid replay detection across tests)
        token_a_cross = await _agent_login(client, agent_a_id, secret_a, tenant_id)
        other_tenant = str(uuid.uuid4())
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={"Authorization": f"Bearer {token_a_cross}", "X-Tenant-ID": other_tenant, "X-Agent-ID": agent_a_id},
            json={"tool": "any.tool", "payload": {}},
        )
        assert resp.status_code == 403, f"Expected 403 for cross-tenant, got {resp.status_code}: {resp.text}"
        assert any(kw in resp.json()["error"] for kw in ("Tenant mismatch", "Cross-tenant", "tenant")), \
            f"Unexpected cross-tenant error: {resp.json()['error']}"

        # 4. Tool not permitted — Agent A has no permissions -> 403 (fresh JTI)
        token_a_exec = await _agent_login(client, agent_a_id, secret_a, tenant_id)
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={"Authorization": f"Bearer {token_a_exec}", "X-Tenant-ID": tenant_id, "X-Agent-ID": agent_a_id},
            json={"tool": "system.run", "payload": {}},
        )
        assert resp.status_code == 403, f"Expected 403 for denied tool, got {resp.status_code}: {resp.text}"
        assert any(
            msg in resp.json()["error"]
            for msg in ["Policy Violation", "Security check failed", "denied", "Permission", "policy",
                        "allow-list", "not in agent", "Tool"]
        ), f"Unexpected policy error: {resp.json()['error']}"

        # 5. Permission scoping: Create Agent C with only db.read permission
        reg_c = await client.post(
            f"{GATEWAY_URL}/agents",
            json={"name": f"sec-agent-c-{uuid.uuid4().hex[:6]}", "description": "Security test agent C", "owner_id": "test"},
            headers=admin_headers,
        )
        assert reg_c.status_code in (200, 201), f"Agent C create failed: {reg_c.text}"
        agent_c_id = reg_c.json()["data"]["id"]

        await client.post(
            f"{GATEWAY_URL}/auth/credentials",
            json={"agent_id": agent_c_id, "secret": secret_c},
            headers=admin_headers,
        )

        # Grant db.read only
        perm_resp = await client.post(
            f"{GATEWAY_URL}/agents/{agent_c_id}/permissions",
            json={"tool_name": "db.read", "action": "ALLOW", "granted_by": "admin"},
            headers=admin_headers,
        )
        assert perm_resp.status_code in (200, 201), f"Permission grant failed: {perm_resp.text}"

        # db.write -> denied (403); fresh JTI each time
        # Tool name must be in X-ACP-Tool header (middleware reads from header/path, not body)
        token_c_write = await _agent_login(client, agent_c_id, secret_c, tenant_id)
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={
                "Authorization": f"Bearer {token_c_write}",
                "X-Tenant-ID": tenant_id,
                "X-Agent-ID": agent_c_id,
                "X-ACP-Tool": "db.write",
            },
            json={"tool": "db.write", "payload": {}},
        )
        assert resp.status_code == 403, f"Expected 403 for db.write, got {resp.status_code}: {resp.text}"

        # db.read -> allowed (200/202) or not implemented (404); fresh JTI
        token_c_read = await _agent_login(client, agent_c_id, secret_c, tenant_id)
        resp = await client.post(
            f"{GATEWAY_URL}/execute",
            headers={
                "Authorization": f"Bearer {token_c_read}",
                "X-Tenant-ID": tenant_id,
                "X-Agent-ID": agent_c_id,
                "X-ACP-Tool": "db.read",
            },
            json={"tool": "db.read", "payload": {}},
        )
        assert resp.status_code in (200, 202, 404), \
            f"Expected allowed/not-implemented for db.read, got {resp.status_code}: {resp.text}"
