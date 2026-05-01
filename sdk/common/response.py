from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standard generic API response envelope."""

    success: bool = True
    data: T | None = None
    error: str | None = None
    meta: dict[str, Any] | None = None

    model_config = ConfigDict(strict=False, from_attributes=True)
