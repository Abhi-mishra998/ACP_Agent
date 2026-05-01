package acp.v1.rate

import rego.v1

# =========================
# RATE LIMITING POLICY
# Enterprise rate/budget enforcement rules
# =========================

default allow := true
default reason := "within rate limits"

# Block agents with critical risk level from sensitive destructive tools
allow := false if {
	lower(input.agent.risk_level) == "critical"
	sensitive_tool
}

# Block if risk score is above absolute ceiling (defense-in-depth with decision engine)
allow := false if {
	input.risk_score >= 1.0
}

# =========================
# SENSITIVE TOOL DEFINITIONS
# =========================

sensitive_tool if {
	destructive_tools := {"delete", "drop", "truncate", "exec", "shell", "sudo", "rm"}
	some t in destructive_tools
	contains(lower(input.tool), t)
}

# =========================
# REASONING
# =========================

reason := "critical risk agent blocked from sensitive tool" if {
	not allow
	lower(input.agent.risk_level) == "critical"
	sensitive_tool
}

reason := "maximum risk threshold exceeded" if {
	not allow
	input.risk_score >= 1.0
}
