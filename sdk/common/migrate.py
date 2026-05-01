"""
Migration safety validator.

Called at service startup AFTER alembic runs. Confirms:
  1. The alembic version table exists (migrations were run).
  2. A revision row exists (upgrade() was not a no-op pass).
  3. Every required table is present (upgrade() actually created them).

Raises RuntimeError on any failure — aborts the lifespan and prevents
the service from accepting traffic with a broken schema.
"""

from __future__ import annotations

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# All tables each service owns.  Single source of truth — update here when
# a new migration adds or removes tables.
REQUIRED_TABLES: dict[str, list[str]] = {
    "audit":    ["audit_logs"],
    "api":      ["api_keys"],
    "usage":    ["usage_records"],
    "registry": ["agents", "permissions"],
    "identity": ["users", "agent_credentials"],
}

# Alembic tracks each service's revision in its own version table so that
# independent per-service DBs don't share a version namespace.
_VERSION_TABLE: dict[str, str] = {
    "audit":    "alembic_version_audit",
    "api":      "alembic_version_api",
    "usage":    "alembic_version_usage",
    "registry": "alembic_version_registry",
    "identity": "alembic_version_identity",
}


def _regclass(table: str) -> str:
    """Return a SQL expression that resolves to NULL when `table` is absent."""
    return f"to_regclass('public.{table}')"


async def check_schema(db: AsyncSession, service_name: str) -> None:
    """
    Verify that migrations were applied correctly for `service_name`.

    Usage in lifespan:
        async with get_session_factory()() as db:
            await check_schema(db, "audit")
    """
    version_table = _VERSION_TABLE[service_name]

    # 1. Version table itself exists?
    row = await db.execute(text(f"SELECT {_regclass(version_table)}"))
    if not row.scalar():
        raise RuntimeError(
            f"[{service_name}] Version table '{version_table}' not found — "
            "run 'alembic upgrade head' for this service"
        )

    # 2. At least one revision row (upgrade() was not a bare `pass`)?
    row = await db.execute(
        text(f"SELECT version_num FROM {version_table} LIMIT 1")  # noqa: S608
    )
    revision = row.scalar()
    if not revision:
        raise RuntimeError(
            f"[{service_name}] '{version_table}' has no revision — "
            "migration ran but upgrade() applied no changes"
        )

    # 3. Every required table present?
    missing: list[str] = []
    for table in REQUIRED_TABLES[service_name]:
        row = await db.execute(text(f"SELECT {_regclass(table)}"))
        if not row.scalar():
            missing.append(table)

    if missing:
        raise RuntimeError(
            f"[{service_name}] Revision {revision!r} applied but tables "
            f"are missing: {missing} — fix upgrade() in the version file"
        )

    logger.info(
        "schema_validated",
        service=service_name,
        revision=revision,
        tables=REQUIRED_TABLES[service_name],
    )
