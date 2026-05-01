"""
ACP Shared Constants
====================
All security-critical constants MUST be defined here exactly once.
Importing from this module is the only permitted way to reference these values.
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Redis key prefixes — any change here propagates everywhere automatically.
# ---------------------------------------------------------------------------

#: Prefix for revoked token hashes. Must match across identity, gateway, and
#: control engine. Changing this in any one place would silently break
#: token revocation — that is why it lives here.
REDIS_REVOKE_PREFIX: str = "acp:revoked:"

#: Prefix for active token hash → subject mapping.
REDIS_TOKEN_PREFIX: str = "acp:token:"

#: Prefix for per-subject (agent/user) active token sets.
REDIS_AGENT_PREFIX: str = "acp:agent:"

# ---------------------------------------------------------------------------
# Redis Stream keys
# ---------------------------------------------------------------------------

#: Canonical audit event stream key.
AUDIT_STREAM_KEY: str = "acp:audit_stream"

#: Dead-letter queue for audit events that fail after retries.
AUDIT_DLQ_KEY: str = "acp:audit_dlq"

#: Consumer group name for the audit stream worker.
AUDIT_CONSUMER_GROUP: str = "acp-audit-workers"


def hash_token(token: str) -> str:
    """Canonical SHA-256 hash for token revocation. Always pass the bare token string, never 'Bearer <token>'."""
    return hashlib.sha256(token.encode()).hexdigest()
