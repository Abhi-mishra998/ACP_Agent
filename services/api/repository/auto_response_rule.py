from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.models.auto_response_rule import AutoResponseRule
from services.api.schemas.auto_response_rule import AutoResponseRuleCreate, AutoResponseRuleUpdate

_SNAPSHOT_FIELDS = (
    "name", "is_active", "priority", "conditions", "actions",
    "cooldown_seconds", "max_triggers_per_hour", "stop_on_match", "mode",
)


class AutoResponseRuleRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list(self, tenant_id: uuid.UUID, *, active_only: bool = False) -> list[AutoResponseRule]:
        q = select(AutoResponseRule).where(AutoResponseRule.tenant_id == tenant_id)
        if active_only:
            q = q.where(AutoResponseRule.is_active.is_(True))
        q = q.order_by(AutoResponseRule.priority.desc(), AutoResponseRule.created_at)
        return list((await self.db.execute(q)).scalars().all())

    async def get(self, rule_id: uuid.UUID, tenant_id: uuid.UUID) -> AutoResponseRule | None:
        return (await self.db.execute(
            select(AutoResponseRule).where(
                AutoResponseRule.id == rule_id,
                AutoResponseRule.tenant_id == tenant_id,
            )
        )).scalar_one_or_none()

    async def create(self, tenant_id: uuid.UUID, payload: AutoResponseRuleCreate) -> AutoResponseRule:
        rule = AutoResponseRule(tenant_id=tenant_id, **payload.model_dump())
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)
        return rule

    async def update(self, rule: AutoResponseRule, payload: AutoResponseRuleUpdate, changed_by: str = "api") -> AutoResponseRule:
        # Snapshot current state before mutation (version history)
        snapshot = {f: getattr(rule, f) for f in _SNAPSHOT_FIELDS}
        history  = list(rule.version_history or [])
        history.append({
            "version":    rule.version,
            "changed_at": datetime.now(UTC).isoformat(),
            "changed_by": changed_by,
            "snapshot":   snapshot,
        })
        # Keep last 20 versions only
        rule.version_history = history[-20:]
        rule.version        += 1

        for key, val in payload.model_dump(exclude_none=True).items():
            setattr(rule, key, val)
        await self.db.commit()
        await self.db.refresh(rule)
        return rule

    async def rollback(self, rule: AutoResponseRule, target_version: int) -> AutoResponseRule:
        history = list(rule.version_history or [])
        entry   = next((h for h in reversed(history) if h["version"] == target_version), None)
        if entry is None:
            raise ValueError(f"Version {target_version} not found in history")
        snap = entry["snapshot"]
        for k, v in snap.items():
            setattr(rule, k, v)
        # Append a rollback record
        history.append({
            "version":    rule.version,
            "changed_at": datetime.now(UTC).isoformat(),
            "changed_by": "rollback",
            "snapshot":   snap,
        })
        rule.version_history = history[-20:]
        rule.version        += 1
        await self.db.commit()
        await self.db.refresh(rule)
        return rule

    async def delete(self, rule: AutoResponseRule) -> None:
        await self.db.delete(rule)
        await self.db.commit()

    async def record_trigger(self, rule_id: uuid.UUID) -> None:
        await self.db.execute(
            update(AutoResponseRule)
            .where(AutoResponseRule.id == rule_id)
            .values(trigger_count=AutoResponseRule.trigger_count + 1,
                    last_triggered_at=datetime.now(UTC))
        )
        await self.db.commit()

    async def record_false_positive(
        self, rule: AutoResponseRule, suppress_min: int
    ) -> AutoResponseRule:
        rule.false_positive_count += 1
        if suppress_min > 0:
            rule.suppressed_until = datetime.now(UTC) + timedelta(minutes=suppress_min)
        await self.db.commit()
        await self.db.refresh(rule)
        return rule
