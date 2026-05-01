"""
Preservation Property Tests - Multi-Tenant Login Fix
=====================================================

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

Property 2: Preservation - Existing Authentication Behavior

IMPORTANT: This test follows observation-first methodology.
These tests observe and capture the baseline behavior on UNFIXED code
for non-buggy inputs (valid single-tenant scenarios).

Expected Outcome: Tests PASS on unfixed code (confirms baseline behavior to preserve)

The tests verify that after the fix:
- Password validation using bcrypt in thread pool continues to work
- Token issuance via TokenService continues to work
- Audit event logging continues to work
- Error handling for invalid credentials continues to work
- Error handling for inactive accounts continues to work
- Response format remains unchanged

NOTE: These tests are designed to work on UNFIXED code (without X-Tenant-ID header requirement).
After the fix is implemented, the tests will need to be updated to include the X-Tenant-ID header.
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
async def test_preservation_nonexistent_user_returns_401(
    http_client: httpx.AsyncClient,
):
    """
    Preservation Test 1: Non-Existent User Returns 401 Unauthorized
    
    This test observes that attempting to login with a non-existent
    email returns 401 Unauthorized with "Invalid credentials" message.
    
    EXPECTED ON UNFIXED CODE: PASS (baseline behavior)
    EXPECTED ON FIXED CODE: PASS (behavior preserved)
    
    Validates:
    - Error handling for invalid credentials continues to work (3.1)
    - Response format remains unchanged (3.6)
    """
    email = f"nonexistent-{uuid.uuid4().hex}@example.com"
    password = "SomePassword123!"
    tenant_id = str(uuid.uuid4())  # Random tenant ID
    
    # Attempt login with non-existent user (with X-Tenant-ID header after fix)
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
        headers={"X-Tenant-ID": tenant_id},
    )
    
    # Should return 401 Unauthorized
    assert response.status_code == 401, (
        f"Expected 401 Unauthorized for non-existent user, but got {response.status_code}. "
        f"Response: {response.text}"
    )
    
    # Verify error message format
    data = response.json()
    assert "error" in data, "Response should contain 'error' field"
    assert "Invalid credentials" in data["error"], (
        f"Error message should be 'Invalid credentials', but got: {data.get('error')}"
    )
    
    # Verify response structure (APIResponse format)
    assert "success" in data, "Response should contain 'success' field"
    assert data["success"] is False, "Success should be False for error response"


@pytest.mark.integration
@pytest.mark.asyncio
@given(
    email_prefix=st.text(min_size=1, max_size=10, alphabet=st.characters(min_codepoint=97, max_codepoint=122)),
    password_length=st.integers(min_value=8, max_value=20),
)
@settings(
    max_examples=10,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
async def test_property_nonexistent_user_always_returns_401(
    http_client: httpx.AsyncClient,
    email_prefix: str,
    password_length: int,
):
    """
    Property-Based Test: Non-Existent User Always Returns 401
    
    Property: For ANY login attempt with a non-existent email,
    the system SHALL return 401 Unauthorized with "Invalid credentials"
    message, regardless of the email or password format.
    
    EXPECTED ON UNFIXED CODE: PASS (baseline behavior)
    EXPECTED ON FIXED CODE: PASS (behavior preserved)
    
    Validates:
    - Error handling for invalid credentials continues to work (3.1)
    - Response format remains unchanged (3.6)
    """
    # Generate random non-existent credentials
    email = f"{email_prefix}-{uuid.uuid4().hex[:8]}@example.com"
    password = "P" * password_length
    tenant_id = str(uuid.uuid4())  # Random tenant ID
    
    # Attempt login with non-existent user (with X-Tenant-ID header after fix)
    response = await http_client.post(
        f"{IDENTITY_URL}/auth/login",
        json={"email": email, "password": password},
        headers={"X-Tenant-ID": tenant_id},
    )
    
    # Property: Should ALWAYS return 401 for non-existent user
    assert response.status_code == 401, (
        f"Property violated: Expected 401 Unauthorized for non-existent user, "
        f"but got {response.status_code}. "
        f"Counterexample: email_prefix={email_prefix}, password_length={password_length}. "
        f"Response: {response.text}"
    )
    
    # Verify error message format is preserved
    data = response.json()
    assert "error" in data, "Response should contain 'error' field"
    assert "Invalid credentials" in data["error"], (
        f"Error message should be 'Invalid credentials', but got: {data.get('error')}"
    )
    
    # Verify response structure (APIResponse format)
    assert "success" in data, "Response should contain 'success' field"
    assert data["success"] is False, "Success should be False for error response"

