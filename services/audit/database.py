"""
services/audit/database.py
===========================
Compatibility shim — re-exports DB utilities and the shared settings object.
The local Settings class is removed to eliminate the duplicate engine instance.
"""

from __future__ import annotations

from sdk.common.config import settings
from sdk.common.db import Base, SessionLocal, get_db

__all__ = ["Base", "SessionLocal", "get_db", "settings"]
