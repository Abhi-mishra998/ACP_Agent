from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from redis.asyncio import Redis

from sdk.common.constants import (
    REDIS_AGENT_PREFIX,
    REDIS_REVOKE_PREFIX,
    REDIS_TOKEN_PREFIX,
)
from services.identity.database import settings
from services.identity.exceptions import (
    AuthenticationError,
    TokenExpiredError,
    TokenRevokedError,
)

TOKEN_TYPE = "ACP_ACCESS"


class TokenService:
    """
    Handles JWT creation, validation, and Redis-backed revocation.

    Token payload includes:
      - jti, sub, tenant_id, org_id, role, typ, iat, exp
      - agent_id  (agent tokens)
      - user_id   (user tokens)
      - agent_status   (agent tokens — embedded at issuance, avoids registry lookup)
      - permissions    (agent tokens — [{tool_name, action}] list, avoids registry lookup)
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        self._secret = settings.JWT_SECRET_KEY
        self._algorithm = settings.JWT_ALGORITHM
        self._expiry_minutes = settings.JWT_EXPIRY_MINUTES

    async def issue(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
        role: str = "agent",
        org_id: uuid.UUID | None = None,
        agent_status: str = "active",
        permissions: list[dict[str, str]] | None = None,
    ) -> tuple[str, int]:
        """
        Create a signed JWT and persist its hash in Redis.

        - org_id defaults to tenant_id when not supplied (backwards-compatible).
        - permissions and agent_status are embedded for agent tokens so the
          execution path never calls Registry at runtime.

        Returns:
            (token_string, expires_in_seconds)
        """
        now = datetime.now(tz=UTC)
        expiry_seconds = self._expiry_minutes * 60
        exp = now + timedelta(seconds=expiry_seconds)

        effective_org_id = org_id or tenant_id

        subject = str(agent_id or user_id)
        payload: dict[str, Any] = {
            "jti":       str(uuid.uuid4()),
            "sub":       subject,
            "tenant_id": str(tenant_id),
            "org_id":    str(effective_org_id),
            "role":      role,
            "typ":       TOKEN_TYPE,
            "iat":       int(now.timestamp()),
            "exp":       int(exp.timestamp()),
        }

        if agent_id:
            payload["agent_id"]     = str(agent_id)
            payload["agent_status"] = agent_status
            # Compact permission list — only what OPA needs
            payload["permissions"]  = [
                {"tool_name": p["tool_name"], "action": p.get("action", "ALLOW")}
                for p in (permissions or [])
            ]
        if user_id:
            payload["user_id"] = str(user_id)

        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        token_hash = self._hash(token)

        redis_key    = f"{REDIS_TOKEN_PREFIX}{token_hash}"
        subject_key  = f"{REDIS_AGENT_PREFIX}{subject}:tokens"

        await self._redis.setex(redis_key, expiry_seconds + 60, subject)
        await self._redis.sadd(subject_key, token_hash)
        await self._redis.expire(subject_key, expiry_seconds + 3600)

        return token, expiry_seconds

    async def verify(self, token: str) -> dict[str, Any]:
        """
        Validate signature, expiry, Redis presence, and non-revocation.

        Returns decoded JWT payload dict.
        Raises TokenExpiredError, TokenRevokedError, AuthenticationError.
        """
        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._algorithm])
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError() from None
        except JWTError:
            raise AuthenticationError("Invalid token") from None

        if payload.get("typ") != TOKEN_TYPE:
            raise AuthenticationError("Invalid token type")

        token_hash  = self._hash(token)
        revoke_key  = f"{REDIS_REVOKE_PREFIX}{token_hash}"
        active_key  = f"{REDIS_TOKEN_PREFIX}{token_hash}"

        if await self._redis.exists(revoke_key):
            raise TokenRevokedError()

        if not await self._redis.exists(active_key):
            raise AuthenticationError("Token not recognized")

        return dict(payload)

    async def revoke(self, token: str) -> bool:
        """Mark token as revoked. Returns True if token was active."""
        try:
            jwt.decode(
                token, self._secret, algorithms=[self._algorithm],
                options={"verify_exp": False},
            )
        except JWTError:
            return False

        token_hash = self._hash(token)
        active_key = f"{REDIS_TOKEN_PREFIX}{token_hash}"
        revoke_key = f"{REDIS_REVOKE_PREFIX}{token_hash}"

        subject_id = await self._redis.get(active_key)
        if subject_id:
            subject_key = f"{REDIS_AGENT_PREFIX}{subject_id.decode()}:tokens"
            await self._redis.srem(subject_key, token_hash)

        await self._redis.setex(revoke_key, 86400, "1")
        await self._redis.delete(active_key)
        return True

    async def revoke_all_for_agent(self, agent_id: uuid.UUID) -> int:
        """Revoke all active tokens for an agent. O(M) where M = active token count."""
        agent_key   = f"{REDIS_AGENT_PREFIX}{agent_id}:tokens"
        token_hashes = await self._redis.smembers(agent_key)

        if not token_hashes:
            return 0

        count = 0
        for h in token_hashes:
            token_hash = h.decode()
            await self._redis.setex(f"{REDIS_REVOKE_PREFIX}{token_hash}", 86400, "1")
            await self._redis.delete(f"{REDIS_TOKEN_PREFIX}{token_hash}")
            count += 1

        await self._redis.delete(agent_key)
        return count

    def decode_unverified(self, token: str) -> dict[str, Any] | None:
        """Decode without Redis check — for introspection only."""
        try:
            return dict(
                jwt.decode(
                    token, self._secret, algorithms=[self._algorithm],
                    options={"verify_exp": False, "verify_signature": True},
                )
            )
        except JWTError:
            return None

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
