"""
ACP Exception Hierarchy
=======================
All ACP exceptions must be defined here. This is the single exception
module for the entire monorepo — both SDK client code and service code.

Previous split (sdk/exceptions.py vs sdk/common/exceptions.py) is resolved:
- sdk/exceptions.py is now a deprecated re-export shim (do not use directly).
- All new code must import from sdk.common.exceptions.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from sdk.common.response import APIResponse

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Base Exceptions
# ---------------------------------------------------------------------------


class ACPError(Exception):
    """Base exception for all ACP errors (both service-layer and SDK client)."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


# ---------------------------------------------------------------------------
# Authentication / Authorisation
# ---------------------------------------------------------------------------


class ACPAuthError(ACPError):
    """Raised when authentication fails (bad token, expired, revoked)."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)


class ACPPermissionError(ACPError):
    """Raised when an authenticated principal lacks permission."""

    def __init__(self, message: str = "Permission denied") -> None:
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


# ---------------------------------------------------------------------------
# Resource Errors
# ---------------------------------------------------------------------------


class ACPNotFoundError(ACPError):
    """Raised when a requested resource does not exist."""

    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__(message, status_code=status.HTTP_404_NOT_FOUND)


class ACPConflictError(ACPError):
    """Raised on resource conflicts (duplicate keys, state violations)."""

    def __init__(self, message: str = "Resource conflict") -> None:
        super().__init__(message, status_code=status.HTTP_409_CONFLICT)


# ---------------------------------------------------------------------------
# SDK Client Errors (previously only in sdk/exceptions.py)
# ---------------------------------------------------------------------------


class ACPPolicyDeniedError(ACPError):
    """Raised by the SDK client when OPA denies an action."""

    def __init__(self, reason: str = "Policy denied") -> None:
        super().__init__(f"Action denied by policy: {reason}", status_code=status.HTTP_403_FORBIDDEN)
        self.reason = reason


class ACPConnectionError(ACPError):
    """Raised by the SDK client when ACP services are unreachable."""

    def __init__(self, message: str = "ACP service unreachable") -> None:
        super().__init__(message, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


# ---------------------------------------------------------------------------
# FastAPI Exception Handlers
# ---------------------------------------------------------------------------


def setup_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers for a FastAPI application."""
    
    from fastapi import HTTPException

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=APIResponse(success=False, error=exc.detail).model_dump(),
        )

    @app.exception_handler(ACPError)
    async def acp_error_handler(_: Request, exc: ACPError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=APIResponse(success=False, error=exc.message).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic v2 puts the original Exception object inside ctx['error'].
        # json.dumps cannot serialize Exception instances → TypeError → 500.
        # Stringify every ctx value so the response is always JSON-safe.
        safe_errors = []
        for err in exc.errors():
            safe_err = dict(err)
            if "ctx" in safe_err and isinstance(safe_err["ctx"], dict):
                safe_err["ctx"] = {k: str(v) for k, v in safe_err["ctx"].items()}
            safe_errors.append(safe_err)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=APIResponse(
                success=False,
                error="Validation failed",
                meta={"details": safe_errors},
            ).model_dump(),
        )

    @app.exception_handler(IntegrityError)
    async def integrity_exception_handler(
        _: Request, exc: IntegrityError
    ) -> JSONResponse:
        logger.error("database_integrity_error", error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=APIResponse(
                success=False, error="Database integrity violation"
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error("unhandled_exception", error=str(exc), path=request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=APIResponse(
                success=False, error="An internal server error occurred"
            ).model_dump(),
        )
