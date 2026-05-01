"""
Canonical Audit Hash Function — Single Source of Truth
=======================================================
ALL audit hash computation MUST use this module.
Never duplicate this logic inline.
"""
from __future__ import annotations

import hashlib
import json


def compute_event_hash(
    prev_hash: str,
    tenant_id: str,
    agent_id: str,
    action: str,
    tool: str | None,
    decision: str,
    request_id: str | None,
) -> str:
    """
    H(prev_hash + stable_json(canonical_fields))
    Fields MUST remain in this exact set and order for backward-compatible verification.
    """
    payload = json.dumps(
        {
            "tenant_id": str(tenant_id),
            "agent_id": str(agent_id),
            "action": str(action),
            "tool": str(tool or ""),
            "decision": str(decision),
            "request_id": str(request_id or ""),
        },
        sort_keys=True,
    )
    return hashlib.sha256(f"{prev_hash}{payload}".encode()).hexdigest()


GENESIS_HASH = "0" * 64
