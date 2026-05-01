import hashlib
import pytest
from unittest.mock import patch
from tests.harness import harness, create_test_token, TEST_AGENT_ID
from sdk.common.constants import REDIS_REVOKE_PREFIX

@pytest.mark.asyncio
async def test_tc1_governance_no_token():
    """[Governance] Execute tool WITHOUT token → must fail 401."""
    response = await harness.gateway.post(
        "/v1/tools/execute",
        json={"tool_name": "read_file", "arguments": {}},
        headers=harness.get_headers(token=None)
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_tc2_governance_no_policy():
    """[Governance] Token present but policy denies → must fail 403."""
    token = create_test_token()

    with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
        mock_eval.return_value = {
            "action": "deny",
            "risk": 1.0,
            "reasons": ["Policy Enforced: No access to this tool"]
        }

        response = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "read_file", "arguments": {}},
            headers=harness.get_headers(token=token)
        )
        assert response.status_code == 403
        assert "Policy Enforced" in response.text


@pytest.mark.asyncio
async def test_tc3_internal_isolation_bypass():
    """[Security] Call Registry directly WITHOUT X-Internal-Secret → must fail 403."""
    # verify_internal_secret raises 403 (authorization error, not authentication)
    response = await harness.registry.get(
        f"/agents/{TEST_AGENT_ID}",
        headers=harness.get_headers(internal=False)   # No secret
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_tc4_token_revoked():
    """[Security] Revoked token → must fail 401."""
    token = create_test_token()
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Pre-load the revocation record into harness MockRedis
    revoke_key = f"{REDIS_REVOKE_PREFIX}{token_hash}"
    harness.redis.data[revoke_key] = "killed"

    try:
        response = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "read_file", "arguments": {}},
            headers=harness.get_headers(token=token)
        )
        assert response.status_code == 401
        assert "Token revoked" in response.text
    finally:
        # Clean up so other tests are not affected
        harness.redis.data.pop(revoke_key, None)


@pytest.mark.asyncio
async def test_tc5_fail_closed_policy_down():
    """[Reliability] Decision engine down → must fail 403 fail-closed."""
    token = create_test_token()

    with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
        mock_eval.side_effect = Exception("Connection Refused")

        response = await harness.gateway.post(
            "/v1/tools/execute",
            json={"tool_name": "read_file", "arguments": {}},
            headers=harness.get_headers(token=token)
        )
        assert response.status_code == 403
        assert "Fail-Closed" in response.text


@pytest.mark.asyncio
async def test_tc7_audit_completeness():
    """[Audit] Every action must generate an audit stream event."""
    token = create_test_token()

    with patch("services.gateway.middleware.service_client.log_audit_stream") as mock_audit:
        mock_audit.return_value = None

        with patch("services.gateway.middleware.service_client.evaluate_decision") as mock_eval:
            mock_eval.return_value = {"action": "allow", "risk": 0.0}
            headers = harness.get_headers(token=token)
            headers["X-ACP-Tool"] = "read_file"  # explicit tool name flows into audit record
            await harness.gateway.post(
                "/v1/tools/execute",
                json={"tool_name": "read_file", "arguments": {}},
                headers=headers
            )

        assert mock_audit.called
        args, kwargs = mock_audit.call_args
        assert args[1]["tool"] == "read_file"


@pytest.mark.asyncio
async def test_tc9_env_validation():
    """[Env] Strict config validation — empty INTERNAL_SECRET must raise ValidationError."""
    from sdk.common.config import ACPSettings
    import os

    with patch.dict(os.environ, {"INTERNAL_SECRET": ""}):
        try:
            ACPSettings()
            pytest.fail("Should have raised ValidationError for empty INTERNAL_SECRET")
        except Exception as e:
            assert "ValidationError" in str(type(e))
