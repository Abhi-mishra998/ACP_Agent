from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.models.api_key import APIKey
from services.api.schemas.api_key import APIKeyCreate


class APIKeyRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(
        self, tenant_id: uuid.UUID, payload: APIKeyCreate
    ) -> tuple[APIKey, str]:
        """
        Generates a new raw API key, stores its hash, and returns both.
        The raw key is NEVER stored.
        """
        # Generate 32-byte secure random key
        raw_key = f"acp_{secrets.token_urlsafe(32)}"
        key_prefix = raw_key[:8]
        key_hash = self._hash_key(raw_key)

        api_key = APIKey(
            tenant_id=tenant_id,
            name=payload.name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            expires_at=payload.expires_at,
        )

        self.db.add(api_key)
        await self.db.commit()
        await self.db.refresh(api_key)

        return api_key, raw_key

    async def list_for_tenant(self, tenant_id: uuid.UUID) -> Sequence[APIKey]:
        stmt = select(APIKey).where(APIKey.tenant_id == tenant_id, APIKey.is_active)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def deactivate(self, tenant_id: uuid.UUID, key_id: uuid.UUID) -> bool:
        stmt = (
            update(APIKey)
            .where(APIKey.id == key_id, APIKey.tenant_id == tenant_id)
            .values(is_active=False)
        )
        result = await self.db.execute(stmt)
        await self.db.commit()
        return result.rowcount > 0

    async def get_by_hash(self, key_hash: str) -> APIKey | None:
        stmt = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def validate(self, raw_key: str) -> APIKey | None:
        """Verify if a raw API key is valid."""
        key_hash = self._hash_key(raw_key)
        api_key = await self.get_by_hash(key_hash)

        if not api_key:
            return None

        # Check expiration
        if api_key.expires_at and api_key.expires_at < datetime.now(
            tz=api_key.expires_at.tzinfo
        ):
            return None

        return api_key

    @staticmethod
    def _hash_key(key: str) -> str:
        """One-way hash for API keys."""
        return hashlib.sha256(key.encode()).hexdigest()
