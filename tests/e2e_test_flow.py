#!/usr/bin/env python3
"""
End-to-End Integration Test — ACP System Flow
==============================================
Tests full flow: User registration → Token generation → Permissions → Policy evaluation
Requires: PostgreSQL, Redis, OPA running locally on standard ports
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx

# Configuration
BASE_URLS = {
    "gateway": "http://localhost:8000",
    "identity": "http://localhost:8000",
    "registry": "http://localhost:8000",
    "policy": "http://localhost:8003",
    "audit": "http://localhost:8000",
    "api": "http://localhost:8005",
}

# Test data
TEST_TENANT_ID = str(uuid.uuid4())
TEST_AGENT_ID = str(uuid.uuid4())
TEST_USER_ID = str(uuid.uuid4())
TEST_TOOL = "system.cleanup"


async def test_flow():
    """Run complete end-to-end test flow."""
    client = httpx.AsyncClient(timeout=30.0)

    try:
        print("\n" + "=" * 80)
        print("ACP END-TO-END TEST FLOW")
        print("=" * 80)

        # ===== PHASE 1: Create User =====
        print("\n[PHASE 1] Create User")
        print("-" * 80)
        user_payload = {
            "email": f"test-user-{uuid.uuid4().hex[:8]}@acp.local",
            "password": "Test123!@#",
            "tenant_id": TEST_TENANT_ID,
            "role": "admin",
        }
        resp = await client.post(
            f"{BASE_URLS['identity']}/auth/users",
            json=user_payload,
            headers={"X-Tenant-ID": TEST_TENANT_ID},
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 201:
            print(f"Response: {resp.text}")
            return False
        user_data = resp.json().get("data", {})
        user_id = user_data.get("id")
        print(f"✓ User created: {user_id}")

        # ===== PHASE 2: User Login =====
        print("\n[PHASE 2] User Login")
        print("-" * 80)
        login_payload = {
            "email": user_payload["email"],
            "password": user_payload["password"],
        }
        resp = await client.post(
            f"{BASE_URLS['identity']}/auth/token",
            json=login_payload,
            headers={"X-Tenant-ID": TEST_TENANT_ID},
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
            return False
        token_data = resp.json().get("data", {})
        user_token = token_data.get("access_token")
        print(f"✓ JWT generated: {user_token[:50]}...")

        # ===== PHASE 3: Register Agent =====
        print("\n[PHASE 3] Register Agent")
        print("-" * 80)
        agent_payload = {
            "name": f"agent-test-{uuid.uuid4().hex[:8]}",
            "description": "Test agent for e2e validation",
            "owner_id": "admin@acp.local",
        }
        resp = await client.post(
            f"{BASE_URLS['registry']}/agents",
            json=agent_payload,
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 201:
            print(f"Response: {resp.text}")
            return False
        agent_data = resp.json().get("data", {})
        agent_id = agent_data.get("id")
        print(f"✓ Agent registered: {agent_id}")

        # ===== PHASE 4: Provision Agent Credentials =====
        print("\n[PHASE 4] Provision Agent Credentials")
        print("-" * 80)
        agent_secret = f"secret-{uuid.uuid4().hex[:16]}"
        cred_payload = {"agent_id": agent_id, "secret": agent_secret}
        resp = await client.post(
            f"{BASE_URLS['identity']}/auth/credentials",
            json=cred_payload,
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 201:
            print(f"Response: {resp.text}")
            return False
        print("✓ Agent credentials provisioned")

        # ===== PHASE 5: Agent Login =====
        print("\n[PHASE 5] Agent Login")
        print("-" * 80)
        agent_login_payload = {"agent_id": agent_id, "secret": agent_secret}
        resp = await client.post(
            f"{BASE_URLS['identity']}/auth/agent/token",
            json=agent_login_payload,
            headers={"X-Tenant-ID": TEST_TENANT_ID},
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
            return False
        agent_token_data = resp.json().get("data", {})
        agent_token = agent_token_data.get("access_token")
        print(f"✓ Agent JWT generated: {agent_token[:50]}...")

        # ===== PHASE 6: Add Permission =====
        print("\n[PHASE 6] Add Permission for Tool")
        print("-" * 80)
        perm_payload = {
            "tool_name": TEST_TOOL,
            "action": "allow",
            "granted_by": "admin@acp.local",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        }
        resp = await client.post(
            f"{BASE_URLS['registry']}/agents/{agent_id}/permissions",
            json=perm_payload,
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 201:
            print(f"Response: {resp.text}")
            return False
        perm_data = resp.json().get("data", {})
        print(f"✓ Permission added: {perm_data.get('id')}")

        # ===== PHASE 7: Retrieve Agent (with cache) =====
        print("\n[PHASE 7] Retrieve Agent Metadata")
        print("-" * 80)
        resp = await client.get(
            f"{BASE_URLS['registry']}/agents/{agent_id}",
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
            return False
        agent_meta = resp.json().get("data", {})
        permissions = agent_meta.get("permissions", [])
        print(f"✓ Agent metadata retrieved with {len(permissions)} permission(s)")

        # ===== PHASE 8: Test Policy Evaluation (allow case) =====
        print("\n[PHASE 8] Policy Evaluation (Allow)")
        print("-" * 80)
        policy_payload = {
            "tenant_id": TEST_TENANT_ID,
            "agent_id": agent_id,
            "tool": TEST_TOOL,
            "policy_version": "v1",
        }
        resp = await client.post(
            f"{BASE_URLS['policy']}/policy/evaluate",
            json=policy_payload,
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
            return False
        policy_result = resp.json().get("data", {})
        allowed = policy_result.get("allowed")
        reason = policy_result.get("reason")
        print(f"✓ Policy Decision: {'ALLOW' if allowed else 'DENY'}")
        print(f"  Reason: {reason}")

        if not allowed:
            print("✗ Expected policy to ALLOW but got DENY")
            return False

        # ===== PHASE 9: Test Policy Evaluation (deny case) =====
        print("\n[PHASE 9] Policy Evaluation (Deny - Unauthorized Tool)")
        print("-" * 80)
        deny_payload = {
            "tenant_id": TEST_TENANT_ID,
            "agent_id": agent_id,
            "tool": "unauthorized.tool",
            "policy_version": "v1",
        }
        resp = await client.post(
            f"{BASE_URLS['policy']}/policy/evaluate",
            json=deny_payload,
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
            return False
        deny_result = resp.json().get("data", {})
        denied = not deny_result.get("allowed")
        print(f"✓ Policy Decision: {'DENY' if denied else 'ALLOW'}")
        print(f"  Reason: {deny_result.get('reason')}")

        if not denied:
            print("✗ Expected policy to DENY but got ALLOW")
            return False

        # ===== PHASE 10: List Audit Logs (wait for async write) =====
        print("\n[PHASE 10] Audit Log Retrieval")
        print("-" * 80)
        await asyncio.sleep(2)  # Wait for Redis stream consumer to persist
        resp = await client.post(
            f"{BASE_URLS['audit']}/audit/logs/search",
            json={"limit": 10},
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Tenant-ID": TEST_TENANT_ID,
            },
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            logs = resp.json().get("data", [])
            print(f"✓ Retrieved {len(logs)} audit log(s)")
        else:
            print("  Note: Audit logs not yet available (expected in async workflow)")

        print("\n" + "=" * 80)
        print("✅ END-TO-END TEST PASSED")
        print("=" * 80 + "\n")
        return True

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False
    finally:
        await client.aclose()


if __name__ == "__main__":
    success = asyncio.run(test_flow())
    exit(0 if success else 1)
