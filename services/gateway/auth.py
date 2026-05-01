"""
ACP Gateway — Local JWT Validator
==================================
Validates tokens locally (no Identity service round-trip).

NOTE (M-11 fix): This class validates JWT signature and expiry ONLY.
Redis revocation checks are performed SEPARATELY in SecurityMiddleware,
which calls redis.exists(REDIS_REVOKE_PREFIX + token_hash) before this validator.
Do NOT assume revocation is checked here.
"""

from __future__ import annotations

from typing import Any

from jose import JWTError, jwt

from sdk.common.config import settings
from sdk.common.constants import REDIS_REVOKE_PREFIX  # H-2 fix: single canonical import
from sdk.common.exceptions import ACPAuthError


class LocalTokenValidator:
    """
    Handles local JWT validation in the Gateway.
    Avoids expensive HTTP round-trips to Identity service on every request.

    Responsibilities (ONLY):
      - Verify JWT signature with shared secret
      - Verify token expiry
      - Verify required claims (agent_id/user_id, tenant_id)

    Revocation (SHA-256 hash + JTI) is checked by SecurityMiddleware AFTER
    this validator returns. Do not add Redis calls here.
    """

    def __init__(self) -> None:
        self._secret = settings.JWT_SECRET_KEY
        self._algorithm = settings.JWT_ALGORITHM

    def validate(self, token: str) -> dict[str, Any]:
        """
        Validate token signature and expiry locally.

        Returns:
            Decoded payload dict if valid.

        Raises:
            ACPAuthError: If signature is invalid, token is expired, or required
                          claims are missing.
        """
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
            )

            # P3-2 FIX: Removed redundant payload.get("exp", 0) < now - 5 check 
            # since python-jose jwt.decode() already handles expiry strictly.

            required = ["sub", "tenant_id", "role", "exp", "jti"]
            for field in required:
                if field not in payload:
                    raise ACPAuthError(f"Invalid token: missing {field}")

            # P3-3 FIX: Agent tokens also have 'sub'. Creating a generic 'user_id'
            # fallback causes downstream type confusion where agent actions look like
            # user actions. We no longer mutate the payload.

            # E2E GAP 2 FIX: Assert org_id consistency
            org_id_str = payload.get("org_id")
            tenant_id_str = payload.get("tenant_id")
            if org_id_str and tenant_id_str:
                import uuid
                from sdk.common.invariants import assert_org_consistency, InvariantViolation
                try:
                    assert_org_consistency(uuid.UUID(org_id_str), uuid.UUID(tenant_id_str), "gateway token validation")
                except InvariantViolation as e:
                    raise ACPAuthError(f"System Integrity Error: {e}")

            return payload

        except jwt.ExpiredSignatureError as exc:
            raise ACPAuthError("Token has expired") from exc
        except JWTError as exc:
            raise ACPAuthError(f"Invalid token: {str(exc)}") from exc


token_validator = LocalTokenValidator()

# Re-export so middleware can import it from here without re-importing constants
__all__ = ["LocalTokenValidator", "token_validator", "REDIS_REVOKE_PREFIX"]
