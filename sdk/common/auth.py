from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

from sdk.common.config import settings

# auto_error=False so we control the error message and status code (403 not 422)
internal_secret_header = APIKeyHeader(name="X-Internal-Secret", auto_error=False)


def extract_bearer_token(authorization: str) -> str | None:
    """
    Extract the raw JWT from an Authorization header value.

    Returns the bare token string (without "Bearer " prefix), or None if the
    header is absent or malformed. All token hashing across the codebase MUST
    use this function so the hash input is always consistent.
    """
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip() or None
    return None


def verify_internal_secret(secret: str | None = Depends(internal_secret_header)) -> str:
    """
    Zero-trust service mesh auth: every internal service call must carry
    X-Internal-Secret matching the shared environment secret.
    Returns 403 (authorization) not 401 (authentication) — the caller is
    identified but not permitted to reach internal services.
    """
    if not secret or secret != settings.INTERNAL_SECRET:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: missing or invalid internal secret",
        )
    return secret
