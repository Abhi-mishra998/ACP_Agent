import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from services.identity.models import User, UserRole

@pytest.mark.asyncio
async def test_user_creation_sets_org_id_defaults_to_tenant(db: AsyncSession):
    """
    Test that creating a user without an explicit org_id 
    automatically sets it to the tenant_id via the model validator.
    """
    tenant_id = uuid.uuid4()
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    
    user = User(
        email=email,
        hashed_password="hashed_password",
        tenant_id=tenant_id,
        role=UserRole.VIEWER,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    assert user.org_id == tenant_id
    assert user.tenant_id == tenant_id

@pytest.mark.asyncio
async def test_user_creation_with_mismatched_org_id_rejected(db: AsyncSession):
    """
    Test that providing a mismatched org_id is rejected by the DB CHECK constraint.
    (SaaS Strict Mode)
    """
    tenant_id = uuid.uuid4()
    org_id = uuid.uuid4() # Different from tenant_id
    email = f"test-{uuid.uuid4().hex[:8]}@example.com"
    
    user = User(
        email=email,
        hashed_password="hashed_password",
        tenant_id=tenant_id,
        org_id=org_id,
        role=UserRole.VIEWER,
    )
    db.add(user)
    
    # This must fail due to the CHECK constraint
    with pytest.raises(Exception) as excinfo:
        await db.commit()
    
    assert "ck_users_org_tenant_match" in str(excinfo.value) or "CheckViolationError" in str(excinfo.value)

@pytest.mark.asyncio
async def test_existing_null_org_id_runtime_fallback(db: AsyncSession):
    """
    Defensive check: With NOT NULL and CHECK constraints active, 
    dirty data insertion should FAIL at the DB level.
    """
    tenant_id = uuid.uuid4()
    email = f"legacy-{uuid.uuid4().hex[:8]}@example.com"
    user_id = uuid.uuid4()
    
    # This should now FAIL due to the NOT NULL constraint I added
    with pytest.raises(Exception) as excinfo:
        await db.execute(text(
            "INSERT INTO users (id, email, hashed_password, tenant_id, role, is_active, created_at, updated_at) "
            "VALUES (:id, :email, :pw, :tenant, :role, true, now(), now())"
        ), {"id": user_id, "email": email, "pw": "pw", "tenant": tenant_id, "role": "VIEWER"})
        await db.commit()
    
    assert "null value in column \"org_id\"" in str(excinfo.value) or "NotNullViolationError" in str(excinfo.value)

@pytest.mark.asyncio
async def test_token_issuance_includes_correct_org_id(db: AsyncSession):
    """
    Integration test: Verify that TokenService.issue (called by login_user)
    correctly embeds the org_id in the JWT.
    """
    from services.identity.token_service import TokenService
    from unittest.mock import AsyncMock
    from jose import jwt
    from services.identity.database import settings
    
    # TokenService expects an async redis client
    redis = AsyncMock()
    redis.setex = AsyncMock()
    token_svc = TokenService(redis)
    
    tenant_id = uuid.uuid4()
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    
    # 1. Issue token
    token, _ = await token_svc.issue(
        tenant_id=tenant_id,
        user_id=user_id,
        org_id=org_id,
        role="VIEWER"
    )
    
    # 2. Decode and verify claims
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    
    assert payload["tenant_id"] == str(tenant_id)
    assert payload["org_id"] == str(org_id)
    assert payload["user_id"] == str(user_id)
    assert payload["role"] == "VIEWER"

@pytest.mark.asyncio
async def test_user_model_invariant_enforcement(db: AsyncSession):
    """
    Ensures that our Rule 'Option A: org_id == tenant_id' is enforced 
    or at least defaults correctly.
    """
    tenant_id = uuid.uuid4()
    user = User(
        email=f"test-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password="pw",
        tenant_id=tenant_id,
        role=UserRole.VIEWER
    )
    # Even before commit, the validator should have run on assignment if it was set to None
    # But since it's only called on attribute assignment, we check after construction.
    # User class doesn't have an __init__ that sets org_id=None explicitly if not passed.
    # However, SQLAlchemy sets it during object loading or flush.
    
    db.add(user)
    await db.flush() # Trigger validators
    
    assert user.org_id == tenant_id
