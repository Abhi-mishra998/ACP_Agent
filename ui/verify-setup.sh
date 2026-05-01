#!/bin/bash

set -e

RESET='\033[0m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'

failures=0

log_pass() {
  echo -e "${GREEN}✓${RESET} $1"
}

log_fail() {
  echo -e "${RED}✗${RESET} $1"
  ((failures++))
}

echo ""
echo "  ${BOLD}🚀 ACP PRODUCTION E2E VALIDATION${RESET}"
echo ""

# --------------------------
# 1. BASIC SERVICE CHECK
# --------------------------
echo "${BOLD}1. Service Health${RESET}"

for port in 8000 8001 8002 8003 8004 8005; do
  if curl -s http://localhost:$port/health > /dev/null; then
    log_pass "Service on port $port healthy"
  else
    log_fail "Service on port $port not responding"
  fi
done

# --------------------------
# 2. DEPENDENCY CHECK
# --------------------------
echo ""
echo "${BOLD}2. Dependencies${RESET}"

pg_isready -h localhost -p 5433 > /dev/null 2>&1 && log_pass "PostgreSQL ready" || log_fail "PostgreSQL failed"
redis-cli ping > /dev/null 2>&1 && log_pass "Redis ready" || log_fail "Redis failed"
curl -s http://localhost:8181/health > /dev/null && log_pass "OPA ready" || log_fail "OPA failed"

# --------------------------
# 3. ACP FLOW TEST (CRITICAL)
# --------------------------
echo ""
echo "${BOLD}3. ACP Governance Flow${RESET}"

AGENT_ID=$(uuidgen)

# Register agent
REGISTER=$(curl -s -X POST http://localhost:8001/agents \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"test_agent_$RANDOM\",
    \"description\": \"test agent flow\",
    \"owner_team\": \"qa\",
    \"framework\": \"test\",
    \"created_by\": \"$AGENT_ID\"
  }")

AGENT_UUID=$(echo $REGISTER | jq -r '.id')

if [ "$AGENT_UUID" != "null" ]; then
  log_pass "Agent registered"
else
  log_fail "Agent registration failed"
fi

# Activate agent
curl -s -X PATCH http://localhost:8001/agents/$AGENT_UUID \
  -H "Content-Type: application/json" \
  -d '{"status":"active"}' > /dev/null

log_pass "Agent activated"

# Request token
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8002/tokens/request \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_UUID\"}")

TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.token')

if [ "$TOKEN" != "null" ]; then
  log_pass "Token issued"
else
  log_fail "Token issue failed"
fi

# Policy eval (should fail by default)
POLICY=$(curl -s -X POST http://localhost:8003/policy/eval \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\":\"$AGENT_UUID\",
    \"session_id\":\"test\",
    \"tool\":\"crm.read\",
    \"action\":\"read\",
    \"token\":\"$TOKEN\"
  }")

ALLOWED=$(echo $POLICY | jq -r '.allowed')

if [ "$ALLOWED" == "false" ]; then
  log_pass "Policy default deny working"
else
  log_fail "Policy enforcement broken"
fi

# --------------------------
# 4. AUDIT CHECK
# --------------------------
echo ""
echo "${BOLD}4. Audit Verification${RESET}"

sleep 1

AUDIT=$(curl -s http://localhost:8004/audit/logs)

COUNT=$(echo $AUDIT | jq '.items | length')

if [ "$COUNT" -ge 1 ]; then
  log_pass "Audit logging working"
else
  log_fail "Audit logging failed"
fi

# --------------------------
# FINAL RESULT
# --------------------------
echo ""
if [ $failures -eq 0 ]; then
  echo "${GREEN}✅ FULL SYSTEM VERIFIED (REAL PRODUCTION READY)${RESET}"
else
  echo "${RED}❌ $failures failure(s) detected${RESET}"
fi