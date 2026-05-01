from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from functools import partial
from typing import Annotated, Any

import bcrypt
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from sdk.common.auth import extract_bearer_token, verify_internal_secret
from sdk.common.db import get_db, get_tenant_id
from sdk.common.deadline import check_deadline
from sdk.common.exceptions import (
    ACPAuthError,
)
from sdk.common.invariants import assert_org_consistency
from sdk.common.redis import get_redis_client
from sdk.common.response import APIResponse
from services.identity.database import settings
from services.identity.exceptions import CredentialNotFoundError
from services.identity.models import AgentCredential, CredentialStatus, User, UserRole
from services.identity.registry_client import registry_client
from services.identity.schemas import (
    AgentLoginRequest,
    CredentialCreateRequest,
    CredentialResponse,
    RevokeResponse,
    TokenIntrospectRequest,
    TokenIntrospectResponse,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from services.identity.token_service import TokenService
from sdk.common.audit_stream import push_audit_event

router = APIRouter(tags=["identity"])
logger = structlog.get_logger(__name__)

# =========================
# REDIS DEPENDENCY
# =========================


async def get_redis() -> AsyncGenerator[Any, None]:
    """Yield a Redis client (Cluster-aware)."""
    r = get_redis_client(settings.REDIS_URL, decode_responses=False)
    try:
        yield r
    finally:
        if hasattr(r, "aclose"):
            await r.aclose()
        else:
            await r.close()


# =========================
# PROVISION CREDENTIALS
# =========================


@router.post(
    "/auth/credentials",
    response_model=APIResponse[CredentialResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Provision credentials for an agent",
    dependencies=[Depends(verify_internal_secret)],
)
async def provision_credentials(
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: CredentialCreateRequest,
    x_tenant_id: Annotated[str, Header()],
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[CredentialResponse]:
    """Admin provisions secrets for an agent."""
    tenant_id = uuid.UUID(x_tenant_id)
    exists = await registry_client.agent_exists(payload.agent_id, tenant_id=tenant_id)
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found or not active in registry",
        )

    secret_str = payload.secret.get_secret_value()
    # Directly use bcrypt library, as passlib is broken here.
    secret_hash = bcrypt.hashpw(secret_str.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )

    # Check for existing credential (active or inactive) to update instead of insert
    # This ensures IDEMPOTENCY as requested in audit-pre.md
    stmt_existing = select(AgentCredential).where(
        AgentCredential.agent_id == payload.agent_id,
        AgentCredential.tenant_id == tenant_id
    )
    res_existing = await db.execute(stmt_existing)
    existing_cred = res_existing.scalar_one_or_none()
    
    if existing_cred:
        # Update existing credentials (idempotent path)
        existing_cred.secret_hash = secret_hash
        existing_cred.status = CredentialStatus.ACTIVE
        existing_cred.is_active = True
        credential = existing_cred
    else:
        # 2b. Hardened creation: explicitly set org_id to match tenant_id
        credential = AgentCredential(
            agent_id=payload.agent_id,
            secret_hash=secret_hash,
            tenant_id=tenant_id,
            org_id=tenant_id,  # 🔥 Mandatory for production constraints
            status=CredentialStatus.ACTIVE,
            is_active=True
        )
        db.add(credential)

    try:
        await db.commit()
    except IntegrityError as err:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Credentials conflict detected (unique constraint)",
        ) from err
    await db.refresh(credential)
    return APIResponse(data=CredentialResponse.model_validate(credential))


@router.post(
    "/auth/users",
    response_model=APIResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create new user",
)
async def create_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: Annotated[UserCreate, Body()],
    authorization: Annotated[str | None, Header()] = None,
    redis: Annotated[Redis | None, Depends(get_redis)] = None,
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[UserResponse]:
    count_res = await db.execute(select(func.count()).select_from(User))
    user_count = count_res.scalar_one()

    if user_count > 0:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Admin token required")
        if not redis:
            raise HTTPException(status_code=500, detail="Redis connection failed")
        token_svc = TokenService(redis)
        try:
            claims = await token_svc.verify(extract_bearer_token(authorization) or "")
            if claims.get("role", "").upper() != UserRole.ADMIN.value:
                raise HTTPException(status_code=403, detail="Admin role required")
        except Exception as err:
            raise HTTPException(status_code=401, detail="Invalid token") from err

    try:
        tenant_id = uuid.UUID(payload.tenant_id)
        org_id = uuid.UUID(payload.org_id) if payload.org_id else tenant_id
        
        # HARDENED: Verify SaaS Strict Invariant before write
        assert_org_consistency(org_id, tenant_id, "user creation")
        
        hashed_password = bcrypt.hashpw(
            payload.password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        user = User(
            email=payload.email,
            hashed_password=hashed_password,
            tenant_id=tenant_id,
            org_id=org_id,
            role=payload.role,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return APIResponse(data=UserResponse.model_validate(user))
    except ValueError as err:
        raise HTTPException(status_code=400, detail="Invalid UUID format") from err
    except IntegrityError as err:
        raise HTTPException(status_code=400, detail="User already exists") from err


@router.get(
    "/auth/me",
    response_model=APIResponse[UserResponse],
    summary="Get current user details",
)
async def get_me(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
    authorization: Annotated[str, Header()],
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[UserResponse]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing auth header")

    token = extract_bearer_token(authorization) or ""
    token_svc = TokenService(redis)
    try:
        claims = await token_svc.verify(token)
    except Exception as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err

    user_id_str = claims.get("user_id")
    if not user_id_str:
        raise HTTPException(
            status_code=403, detail="Token is not associated with a User account"
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError as err:
        raise HTTPException(
            status_code=400, detail="Invalid user ID format in token"
        ) from err

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return APIResponse(data=UserResponse.model_validate(user))


@router.post(
    "/auth/token",
    response_model=APIResponse[TokenResponse],
    summary="Login agent and return JWT",
)
async def login_agent(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
    payload: AgentLoginRequest,
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[TokenResponse]:
    """Agent logs in with agent_id and secret."""
    result = await db.execute(
        select(AgentCredential).where(AgentCredential.agent_id == payload.agent_id)
    )
    credential = result.scalar_one_or_none()

    if not credential or not credential.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent credentials or inactive agent",
        )

    # Verify secret — run synchronous bcrypt in thread pool to avoid blocking event loop (PE-5)
    secret_bytes = payload.secret.get_secret_value().encode("utf-8")
    hash_bytes = credential.secret_hash.encode("utf-8")
    match = await asyncio.get_event_loop().run_in_executor(
        None, partial(bcrypt.checkpw, secret_bytes, hash_bytes)
    )
    if not match:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent credentials",
        )

    # Fetch agent metadata from Registry so we can embed permissions + status
    # in the JWT — this eliminates all Registry calls from the execute hot-path.
    agent_status = "active"
    permissions: list[dict] = []
    try:
        agent_data = await registry_client.get_agent(credential.agent_id, tenant_id=credential.tenant_id)
        inner = agent_data.get("data", agent_data)
        agent_status = inner.get("status", "active")
        permissions = [
            {"tool_name": p["tool_name"], "action": p.get("action", "ALLOW")}
            for p in inner.get("permissions", [])
        ]
    except Exception as exc:
        logger.warning("registry_metadata_fetch_failed", agent_id=str(credential.agent_id), error=str(exc))
        pass  # Registry unavailable — token still issued; gateway falls back to cache

    # Resolve org_id from the Tenant table (if migrated); default to tenant_id
    org_id = credential.org_id

    token_svc = TokenService(redis)
    token, expires_in = await token_svc.issue(
        tenant_id=credential.tenant_id,
        agent_id=credential.agent_id,
        role="agent",
        org_id=org_id,
        agent_status=agent_status,
        permissions=permissions,
    )

    await push_audit_event(
        redis=redis,
        tenant_id=credential.tenant_id,
        agent_id=credential.agent_id,
        action="token_issue",
        metadata={"role": "agent", "type": "access_token", "permissions_embedded": len(permissions)}
    )

    return APIResponse(
        data=TokenResponse(
            access_token=token,
            expires_in=expires_in,
            tenant_id=credential.tenant_id,
            agent_id=credential.agent_id,
            role="agent",
        )
    )


@router.post(
    "/auth/login",
    summary="Login user and return JWT",
)
async def login_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    redis: Annotated[Redis, Depends(get_redis)],
    payload: UserLogin,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[TokenResponse]:
    email = payload.email.strip().lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
        
    if x_tenant_id:
        try:
            tenant_uuid = uuid.UUID(x_tenant_id)
            if user.tenant_id != tenant_uuid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials or tenant mismatch"
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Tenant UUID"
            )

    # PE-5: bcrypt is CPU-bound, run in thread pool
    pw_bytes = payload.password.encode("utf-8")
    stored_hash = user.hashed_password.encode("utf-8")
    pw_valid = await asyncio.get_event_loop().run_in_executor(
        None, partial(bcrypt.checkpw, pw_bytes, stored_hash)
    )
    if not pw_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # HARDENED: We fail-fast on data corruption. If org_id is NULL, we refuse to issue a token.
    org_id = user.org_id
    if org_id is None:
        logger.error("SECURITY_CRITICAL: org_id is NULL for user", user_id=str(user.id), tenant_id=str(user.tenant_id))
        raise HTTPException(
            status_code=500,
            detail="System integrity error: inconsistent account metadata"
        )
    
    # HARDENED: Verify SaaS Strict Invariant on read/login
    assert_org_consistency(org_id, user.tenant_id, "user login")

    token_svc = TokenService(redis)
    token, expires_in = await token_svc.issue(
        tenant_id=user.tenant_id, user_id=user.id, role=user.role, org_id=org_id
    )

    await push_audit_event(
        redis=redis,
        tenant_id=user.tenant_id,
        agent_id=None,
        action="user_login",
        metadata={"role": user.role, "user_id": str(user.id)},
    )

    return APIResponse(
        data=TokenResponse(
            access_token=token,
            expires_in=expires_in,
            tenant_id=str(user.tenant_id),
            role=user.role,
        )
    )


# =========================
# INTROSPECT / VERIFY
# =========================


@router.post(
    "/auth/introspect",
    response_model=APIResponse[TokenIntrospectResponse],
    summary="Verify token validity",
)
async def introspect(
    request: Request,
    redis: Annotated[Redis, Depends(get_redis)],
    payload: TokenIntrospectRequest,
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[TokenIntrospectResponse]:
    # AS-4 FIX: Rate limit introspect to prevent brute-force token scanning
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"acp:ratelimit:introspect:{client_ip}"
    count_raw = await redis.incr(rate_key)
    if count_raw == 1:
        await redis.expire(rate_key, 60)
    if count_raw > 30:  # 30 introspects per minute per IP
        raise HTTPException(status_code=429, detail="Introspect rate limit exceeded")

    token_svc = TokenService(redis)
    try:
        claims = await token_svc.verify(payload.token)
        return APIResponse(
            data=TokenIntrospectResponse(
                active=True,
                agent_id=uuid.UUID(claims["agent_id"])
                if "agent_id" in claims
                else None,
                user_id=uuid.UUID(claims["user_id"]) if "user_id" in claims else None,
                tenant_id=uuid.UUID(claims["tenant_id"]),
                role=claims.get("role"),
                exp=claims.get("exp"),
                iat=claims.get("iat"),
            )
        )
    except HTTPException:
        raise
    except Exception:
        return APIResponse(data=TokenIntrospectResponse(active=False))


# =========================
# REVOKE
# =========================


@router.post(
    "/auth/revoke",
    response_model=APIResponse[RevokeResponse],
    summary="Revoke all tokens for agent",
)
async def revoke_all(
    redis: Annotated[Redis, Depends(get_redis)],
    db: Annotated[AsyncSession, Depends(get_db)],
    agent_id: uuid.UUID,
    authorization: Annotated[str, Header()],
) -> APIResponse[RevokeResponse]:
    """AS-5: Authenticated revoke — requires ADMIN or SECURITY role."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token_svc = TokenService(redis)
    try:
        claims = await token_svc.verify(extract_bearer_token(authorization) or "")
        role = claims.get("role", "").upper()
        if role not in ("ADMIN", "SECURITY"):
            raise HTTPException(status_code=403, detail="ADMIN or SECURITY role required")
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err
    result = await db.execute(
        select(AgentCredential).where(AgentCredential.agent_id == agent_id)
    )
    credential = result.scalar_one_or_none()
    if not credential:
        raise CredentialNotFoundError()

    # Ownership check: caller must belong to the same tenant as the agent
    try:
        claims_tenant_id = uuid.UUID(claims.get("tenant_id", ""))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=403, detail="Invalid tenant in token")
    if credential.tenant_id != claims_tenant_id:
        raise HTTPException(status_code=403, detail="Cannot revoke credentials for agent in another tenant")

    credential.status = CredentialStatus.REVOKED
    credential.is_active = False
    await db.commit()

    token_svc = TokenService(redis)
    count = await token_svc.revoke_all_for_agent(agent_id)

    # RULE 2: Every action is audited
    await push_audit_event(
        redis=redis,
        tenant_id=credential.tenant_id,
        agent_id=agent_id,
        action="token_revoke_all",
        metadata={"count": count}
    )

    return APIResponse(
        data=RevokeResponse(
            agent_id=agent_id, revoked=True, message=f"Revoked {count} tokens"
        )
    )


@router.post(
    "/auth/refresh",
    response_model=APIResponse[TokenResponse],
    summary="Refresh access token",
)
async def refresh_token(
    redis: Annotated[Redis, Depends(get_redis)],
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str, Header()],
    _: Annotated[bool, Depends(check_deadline)] = True,
) -> APIResponse[TokenResponse]:
    """Refresh an access token using current token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing auth header")

    token = extract_bearer_token(authorization) or ""
    token_svc = TokenService(redis)

    try:
        claims = await token_svc.verify(token)
    except Exception as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err

    tenant_id = uuid.UUID(claims.get("tenant_id", ""))
    agent_id = uuid.UUID(claims["agent_id"]) if "agent_id" in claims else None
    user_id = uuid.UUID(claims["user_id"]) if "user_id" in claims else None
    role = claims.get("role", "viewer")

    # 1. HARDENING: Re-validate status in DB
    if agent_id:
        stmt = select(AgentCredential).where(
            AgentCredential.agent_id == agent_id,
            AgentCredential.tenant_id == tenant_id
        )
        res = await db.execute(stmt)
        cred = res.scalar_one_or_none()
        if not cred or cred.status != CredentialStatus.ACTIVE:
            raise HTTPException(status_code=401, detail="Agent credentials are no longer active")
    elif user_id:
        stmt = select(User).where(User.id == user_id, User.tenant_id == tenant_id)
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()
        if not user or user.status != "ACTIVE":
            raise HTTPException(status_code=401, detail="User account is no longer active")

    # 2. Revoke old token
    await token_svc.revoke(token)

    # Issue new token
    new_token, expires_in = await token_svc.issue(
        tenant_id=tenant_id,
        agent_id=agent_id,
        user_id=user_id,
        role=role
    )

    return APIResponse(
        data=TokenResponse(
            access_token=new_token,
            expires_in=expires_in,
            tenant_id=str(tenant_id),
            agent_id=str(agent_id) if agent_id else None,
            role=role,
        )
    )


# =========================
# TENANT MANAGEMENT
# =========================


from services.identity.models import Tenant, TenantTier  # noqa: E402 — avoids circular at module top


_TIER_RPM_DEFAULTS: dict[str, int] = {
    "basic":      60,
    "pro":       300,
    "enterprise": 1000,
}


@router.get(
    "/auth/tenants/{tenant_id}",
    summary="Get tier and rate-limit metadata for a tenant",
    dependencies=[Depends(verify_internal_secret)],
)
async def get_tenant_metadata(
    tenant_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Called by the Gateway ServiceClient to resolve real tier + rpm_limit.
    Falls back to basic defaults if no row exists yet.
    """
    result = await db.execute(select(Tenant).where(Tenant.tenant_id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        return {
            "tenant_id": str(tenant_id),
            "org_id":    str(tenant_id),
            "tier":      "basic",
            "rpm_limit": _TIER_RPM_DEFAULTS["basic"],
            "status":    "active",
        }

    effective_rpm = tenant.rpm_limit or _TIER_RPM_DEFAULTS.get(tenant.tier.value, 60)
    return {
        "tenant_id": str(tenant.tenant_id),
        "org_id":    str(tenant.org_id),
        "tier":      tenant.tier.value,
        "rpm_limit": effective_rpm,
        "status":    "active" if tenant.is_active else "suspended",
    }


@router.post(
    "/auth/tenants",
    summary="Create or update tenant tier/rpm_limit",
    dependencies=[Depends(verify_internal_secret)],
    status_code=201,
)
async def upsert_tenant(
    db: Annotated[AsyncSession, Depends(get_db)],
    body: dict,
) -> dict:
    """
    Create or update a tenant record. Used by provisioning scripts.
    Body: {tenant_id, org_id, tier, rpm_limit, name}
    """

    tenant_id_val = uuid.UUID(body["tenant_id"])
    org_id_val    = uuid.UUID(body.get("org_id", body["tenant_id"]))
    tier_val      = body.get("tier", "basic")
    rpm_val       = int(body.get("rpm_limit", _TIER_RPM_DEFAULTS.get(tier_val, 60)))
    name_val      = body.get("name", "Default Tenant")

    result = await db.execute(select(Tenant).where(Tenant.tenant_id == tenant_id_val))
    existing = result.scalar_one_or_none()

    if existing:
        existing.tier      = TenantTier(tier_val)
        existing.rpm_limit = rpm_val
        existing.name      = name_val
    else:
        db.add(Tenant(
            org_id=org_id_val,
            tenant_id=tenant_id_val,
            name=name_val,
            tier=TenantTier(tier_val),
            rpm_limit=rpm_val,
        ))

    await db.commit()
    return {"status": "ok", "tenant_id": str(tenant_id_val), "tier": tier_val, "rpm_limit": rpm_val}
