import uuid
from unittest.mock import AsyncMock, patch

import pytest

from services.gateway.client import service_client


@pytest.mark.asyncio
async def test_policy_fallback_chaos():
    """
    Test Case 2: Kill Policy Service
    Expected: Policy evaluation falls back to Circuit Breaker deny, avoiding a gateway crash.
    """
    agent_id = uuid.uuid4()
    tenant_id = uuid.uuid4()

    # Force Circuit breaker to open state
    service_client._opa_cb.record_failure()
    service_client._opa_cb.record_failure()
    service_client._opa_cb.record_failure()
    service_client._opa_cb.record_failure()
    service_client._opa_cb.record_failure()

    assert service_client._opa_cb.is_open is True

    result = await service_client.evaluate_policy(
        tenant_id=tenant_id,
        agent_id=agent_id,
        tool="test_tool",
        risk_score=0.1
    )

    # It should fail-safe deny since CB is open and no cache exists
    assert result["allowed"] is False
    assert "fail safe deny" in result["reason"]

@pytest.mark.asyncio
async def test_identity_fallback_chaos():
    """
    Test Case X: Kill Identity Service
    Expected: Gateway falls back to local JWT validation without remote API dependence.
    """
    token = "ey..." # Mock structural JWT

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # Simulate network timeout / 500 error from Identity Service
        mock_post.side_effect = Exception("Identity Service Connection Terminated")

        # Test the fallback
        result = await service_client.introspect_token(token)

        # We expect the local fallback to attempt decode, catch JWT structural error, and deny safely instead of crashing
        assert result.get("active") is False
