from __future__ import annotations

import json
import uuid

from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis


class AgentProfile(BaseModel):
    """The dynamic profile of an AI agent's baseline behavior."""

    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    baseline_tools: set[str] = Field(default_factory=set)
    avg_velocity: float = 0.0
    risk_baseline: float = 0.0
    last_updated: float = 0.0

    model_config = ConfigDict(strict=True)

    def to_json(self) -> str:
        data = self.model_dump()
        data["agent_id"] = str(data["agent_id"])
        data["tenant_id"] = str(data["tenant_id"])
        data["baseline_tools"] = list(data["baseline_tools"])
        return json.dumps(data)

    @classmethod
    def from_json(cls, data_str: str) -> AgentProfile:
        data = json.loads(data_str)
        data["agent_id"] = uuid.UUID(data["agent_id"])
        data["tenant_id"] = uuid.UUID(data["tenant_id"])
        data["baseline_tools"] = set(data["baseline_tools"])
        return cls(**data)


class Profiler:
    """Handles persistence and dynamic updating of agent behavior profiles."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def _get_key(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> str:
        return f"acp:behavior:profile:t:{str(tenant_id)}:a:{str(agent_id)}"

    async def get_profile(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> AgentProfile:
        key = self._get_key(tenant_id, agent_id)
        data = await self.redis.get(key)
        if not data:
            return AgentProfile(agent_id=agent_id, tenant_id=tenant_id)
        return AgentProfile.from_json(data)

    async def update_profile(
        self, tenant_id: uuid.UUID, agent_id: uuid.UUID, current_velocity: float, tool: str
    ) -> AgentProfile:
        """Update the profile based on new observations."""
        profile = await self.get_profile(tenant_id, agent_id)

        # 1. Update baseline tools (add if new)
        profile.baseline_tools.add(tool)

        # 2. Moving average for velocity (alpha=0.1)
        if profile.avg_velocity == 0:
            profile.avg_velocity = current_velocity
        else:
            profile.avg_velocity = (profile.avg_velocity * 0.9) + (current_velocity * 0.1)

        key = self._get_key(tenant_id, agent_id)
        await self.redis.set(key, profile.to_json())
        return profile
