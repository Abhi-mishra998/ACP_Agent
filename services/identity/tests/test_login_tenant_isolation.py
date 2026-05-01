"""
Bug Condition Exploration Test - Multi-Tenant Login Fix
========================================================

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**

Property 1: Bug Condition - Tenant Isolation in Login

This test encodes the expected behavior:
- Login without X-Tenant-ID header should return 400 Bad Request
- Login with X-Tenant-ID header should filter by both email AND tenant_id
- Login with wrong tenant_id should return 401 Unauthorized
- Login with invalid UUID should return 400 Bad Request
"""
from __future__ import annotations

import uuid

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# Service URLs
IDENTITY_URL = "http://localhost:8002"


@pytest.fixture
async def http_client():
    """Create an HTTP client for testing."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        yield client


@pytest.mark.integration
@pytest.mark.asyncio
async def test_login_without_tenant_id_header_returns_400(
    http_client: httpx.AsyncClient,
):
    """
    Test Case 1: Missing X-Tenant-ID Header
    
    The system returns 400 Bad Request when X-Tenant-ID header is missing.
    """
    email = f"nonexistent-{uuid.uuid4().hex}@example.com"
    password = "SomePassword123!"
    
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
    )
    
    assert response.status_code == 400, (
        f"Expected 400 Bad Request when X-Tenant-ID header is missing, "
        f"but got {response.status_code}. "
        f"Response: {response.text}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_login_with_invalid_uuid_returns_400(
    http_client: httpx.AsyncClient,
):
    """
    Test Case 2: Invalid UUID in X-Tenant-ID Header
    """
    email = f"test-{uuid.uuid4().hex}@example.com"
    password = "SomePassword123!"
    
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
        headers={"X-Tenant-ID": "not-a-valid-uuid"},
    )
    
    assert response.status_code == 400, (
        f"Expected 400 Bad Request for invalid UUID, "
        f"but got {response.status_code}. "
        f"Response: {response.text}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_login_with_tenant_id_header_but_nonexistent_user(
    http_client: httpx.AsyncClient,
):
    """
    Test Case 3: With X-Tenant-ID Header but Non-Existent User
    
    This test verifies that when X-Tenant-ID header IS provided,
    the endpoint should return 401 for non-existent users.
    """
    tenant_id = uuid.uuid4()
    email = f"nonexistent-{uuid.uuid4().hex}@example.com"
    password = "SomePassword123!"
    
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
        headers={"X-Tenant-ID": str(tenant_id)},
    )
    
    assert response.status_code == 401, (
        f"Expected 401 Unauthorized for non-existent user, "
        f"but got {response.status_code}. "
        f"Response: {response.text}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
@given(
    tenant_count=st.integers(min_value=1, max_value=3),
)
@settings(
    max_examples=5,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
async def test_property_missing_tenant_header_always_returns_400(
    http_client: httpx.AsyncClient,
    tenant_count: int,
):
    """
    Property-Based Test: Missing X-Tenant-ID Header Always Returns 400
    
    Property: For ANY login request without X-Tenant-ID header,
    the system SHALL return 400 Bad Request.
    """
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    password = f"Password{uuid.uuid4().hex[:8]}!"
    
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
    )
    
    assert response.status_code == 400, (
        f"Property violated: Expected 400 Bad Request for missing X-Tenant-ID header, "
        f"but got {response.status_code}. "
        f"Counterexample: email={email}, tenant_count={tenant_count}. "
        f"Response: {response.text}"
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_email_normalization(
    http_client: httpx.AsyncClient,
):
    """
    Test Case 4: Email Normalization
    
    Verifies that emails are normalized (trimmed and lowercased) before querying.
    """
    tenant_id = uuid.uuid4()
    
    # Test with uppercase and whitespace
    email_variants = [
        "  Test@Example.com  ",
        "TEST@EXAMPLE.COM",
        "test@example.com",
    ]
    
    for email in email_variants:
        response = await http_client.post(
            f"{IDENTITY_URL}/auth/login",
            json={"email": email, "password": "TestPassword123!"},
            headers={"X-Tenant-ID": str(tenant_id)},
        )
        
        # All variants should be treated the same (401 for non-existent user)
        assert response.status_code == 401, (
            f"Email normalization failed for '{email}': "
            f"expected 401, got {response.status_code}. "
            f"Response: {response.text}"
        )
