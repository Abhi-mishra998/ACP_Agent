from enum import StrEnum


class AgentStatus(StrEnum):
    """Refined agent status enum for system-wide consistency."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    THROTTLED = "THROTTLED"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


class PermissionAction(StrEnum):
    """Centralized permission actions."""
    ALLOW = "ALLOW"
    DENY = "DENY"
