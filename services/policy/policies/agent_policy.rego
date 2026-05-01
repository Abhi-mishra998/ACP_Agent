package acp.v1.agent

import rego.v1

# =========================
# DEFAULT DECISION
# =========================

default allow := false
default reason := "no match found"

# =========================
# MAIN ENTRY POINT
# =========================

main := {
	"allow": allowed,
	"reason": msg,
	"risk_adjustment": adjustment,
}

# =========================
# ALLOW LOGIC
# =========================

default allowed := false

allowed if {
	# 1. Agent must be active
	lower(input.agent.status) == "active"

	# 2. Agent must not be quarantined or terminated
	not agent_suspended

	# 3. Find a matching allow permission for the requested tool
	some perm in input.agent.permissions
	perm.tool_name == input.tool
	lower(perm.action) == "allow"

	# 4. No deny override for this tool
	not has_deny_permission

	# 5. Risk score must be below critical threshold
	not input.risk_score >= 0.95
}

# Allow wildcard permission (e.g., management/system agents)
allowed if {
	lower(input.agent.status) == "active"
	not agent_suspended

	some perm in input.agent.permissions
	perm.tool_name == "*"
	lower(perm.action) == "allow"

	not has_deny_permission
	not input.risk_score >= 0.95
}

# Default allow variable (queried by data/acp/v1/agent/allow)
allow := allowed

# =========================
# HELPERS
# =========================

agent_suspended if {
	lower(input.agent.status) == "quarantined"
}

agent_suspended if {
	lower(input.agent.status) == "terminated"
}

has_deny_permission if {
	some perm in input.agent.permissions
	perm.tool_name == input.tool
	lower(perm.action) == "deny"
}

# =========================
# RISK ADJUSTMENT
# =========================

default adjustment := 0.0

# Escalate risk for high-risk agents attempting sensitive tools
risk_adjustment := 0.2 if {
	lower(input.agent.risk_level) == "high"
	input.risk_score >= 0.5
}

risk_adjustment := 0.15 if {
	lower(input.agent.risk_level) == "medium"
	input.risk_score >= 0.7
}

# Reduce risk for well-known low-risk agents (P-4 FIX: bounds-safe, no negative bypass)
risk_adjustment := -0.1 if {
	lower(input.agent.risk_level) == "low"
	input.risk_score < 0.2
	allowed
}

# =========================
# REASONING
# =========================

default msg := "no allow permission found for tool"

msg := "permission granted" if {
	allowed
}

msg := "agent is suspended" if {
	not allowed
	agent_suspended
}

msg := "agent is not active" if {
	not allowed
	not agent_suspended
	lower(input.agent.status) != "active"
}

msg := "explicit deny permission for tool" if {
	not allowed
	not agent_suspended
	has_deny_permission
}

msg := "risk score exceeds critical threshold" if {
	not allowed
	input.risk_score >= 0.95
}
