"""
services/identity/database.py
==============================
Compatibility shim — re-exports DB utilities and the shared settings object.
IdentitySettings is removed; use sdk.common.config.settings instead.
"""

from __future__ import annotations

from sdk.common.config import settings
from sdk.common.db import Base, SessionLocal, get_db

__all__ = ["Base", "SessionLocal", "get_db", "settings"]
