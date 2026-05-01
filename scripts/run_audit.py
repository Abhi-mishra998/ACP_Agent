import asyncio
import sys
import os
from unittest.mock import patch, AsyncMock

# Add current dir to path
sys.path.append(os.getcwd())

# Set dummy environment variables to pass strict validation for testing
import os
os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@localhost/db"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["INTERNAL_SECRET"] = "supersecret123"
os.environ["JWT_SECRET_KEY"] = "54ea24ad3c70807c102fcdaf5ba389230690ceaf8a7be9ad758cc2eaabcb82ad"
os.environ["INTELLIGENCE_SERVICE_URL"] = "http://localhost:8000"
os.environ["LEARNING_SERVICE_URL"] = "http://localhost:8000"
os.environ["DECISION_SERVICE_URL"] = "http://localhost:8000"
os.environ["INSIGHT_SERVICE_URL"] = "http://localhost:8000"
os.environ["BEHAVIOR_SERVICE_URL"] = "http://localhost:8000"
os.environ["API_SERVICE_URL"] = "http://localhost:8000"
os.environ["REGISTRY_SERVICE_URL"] = "http://localhost:8000"
os.environ["IDENTITY_SERVICE_URL"] = "http://localhost:8000"
os.environ["POLICY_SERVICE_URL"] = "http://localhost:8000"
os.environ["AUDIT_SERVICE_URL"] = "http://localhost:8000"
os.environ["USAGE_SERVICE_URL"] = "http://localhost:8000"
os.environ["FORENSICS_SERVICE_URL"] = "http://localhost:8000"

from tests.harness import harness, create_test_token, TEST_TENANT_ID, TEST_AGENT_ID

async def run_audit():
    print("🚀 Starting ACP Production Readiness Audit (Gatekeeper Mode)\n")
    results = []
    
    # Common mock payload
    mock_payload = {
        "sub": str(TEST_AGENT_ID),
        "agent_id": str(TEST_AGENT_ID),
        "tenant_id": str(TEST_TENANT_ID),
        "role": "admin", # Elevate to pass inference checks
        "jti": "mock-jti",
        "exp": 9999999999
    }

    # TC-1: Governance No Token
    print("TC-1: Governance - No Token execution", end="... ")
    resp = await harness.gateway.post(
        "/v1/tools/execute",
        json={"tool_name": "read_file", "arguments": {}},
        headers=harness.get_headers(token=None)
    )
    if resp.status_code == 401:
        print("✅ PASS")
        results.append(True)
    else:
        print(f"❌ FAIL (Status: {resp.status_code})")
        results.append(False)

    # TC-2: Governance No Policy
    print("TC-2: Governance - No Policy access", end="... ")
    token = "mock-token"
    with patch("services.gateway.middleware.token_validator.validate", return_value=mock_payload):
        with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
            mock_eval.return_value = {"action": "deny", "risk": 1.0, "reasons": ["Policy Deny"]}
            resp = await harness.gateway.post(
                "/v1/tools/execute",
                json={"tool_name": "read_file", "arguments": {}},
                headers=harness.get_headers(token=token)
            )
            if resp.status_code == 403:
                print("✅ PASS")
                results.append(True)
            else:
                print(f"❌ FAIL (Status: {resp.status_code})")
                results.append(False)

    # TC-3: Internal Isolation
    print("TC-3: Security - Internal Isolation", end="... ")
    resp = await harness.registry.get(
        f"/agents/{TEST_AGENT_ID}",
        headers=harness.get_headers(internal=False)
    )
    if resp.status_code == 401:
        print("✅ PASS")
        results.append(True)
    else:
        print(f"❌ FAIL (Status: {resp.status_code})")
        results.append(False)

    # TC-4: Token Revoked
    print("TC-4: Security - Token Revoked", end="... ")
    token = create_test_token()
    
    # We patch the 'redis' instance that was passed to the middleware during startup
    with patch("services.gateway.main.redis") as mock_redis:
        mock_redis.exists = AsyncMock(return_value=True) # Revoked
        resp = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "read_file", "arguments": {}},
            headers=harness.get_headers(token=token)
        )
        if resp.status_code == 401:
            print("✅ PASS")
            results.append(True)
        else:
            print(f"❌ FAIL (Status: {resp.status_code})")
            results.append(False)

    # TC-5: Fail-Closed
    print("TC-5: Reliability - Fail-Closed (Rule 4)", end="... ")
    token = "mock-token"
    # Ensure role is admin to pass inference/policy checks
    admin_payload = {**mock_payload, "role": "admin"}
    with patch("services.gateway.middleware.token_validator.validate", return_value=admin_payload):
        with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
            mock_eval.side_effect = Exception("Service Down")
            resp = await harness.gateway.post(
                "/v1/tools/execute",
                json={"tool_name": "read_file", "arguments": {}},
                headers=harness.get_headers(token=token)
            )
            # Expecting 403 AND my specific Fail-Closed reason
            if resp.status_code == 403 and "Fail-Closed" in resp.text:
                print("✅ PASS")
                results.append(True)
            else:
                print(f"❌ FAIL (Status: {resp.status_code}, Body: {resp.text[:100]})")
                results.append(False)

    # Final Result
    total = len(results)
    passed = sum(1 for r in results if r)
    print(f"\nAudit Summary: {passed}/{total} tests passed.")
    if passed == total:
        print("✅ SYSTEM VERDICT: PRODUCTION READY")
    else:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(run_audit())
