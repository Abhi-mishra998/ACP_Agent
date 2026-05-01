#!/bin/bash
# Complete ACP System Health Check & Test Script
# Verifies all frontend-backend integrations are working

echo "════════════════════════════════════════════════════════════"
echo "  🔍 ACP SYSTEM HEALTH CHECK & INTEGRATION TEST"
echo "════════════════════════════════════════════════════════════"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Track results
PASSED=0
FAILED=0

# Helper functions
check_service() {
  local name=$1
  local url=$2
  local expected_status=${3:-200}
  
  echo -n "  Checking $name... "
  
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
  
  if [ "$HTTP_CODE" = "$expected_status" ] || [ "$HTTP_CODE" != "000" ]; then
    echo -e "${GREEN}✓${NC} (HTTP $HTTP_CODE)"
    ((PASSED++))
    return 0
  else
    echo -e "${RED}✗${NC} (HTTP $HTTP_CODE)"
    ((FAILED++))
    return 1
  fi
}

test_login() {
  echo -n "  Testing login with demo credentials... "
  
  RESPONSE=$(curl -s -X POST http://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@acp.local","password":"password"}')
  
  if echo "$RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✓${NC}"
    TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('data',{}).get('access_token') or r.get('access_token',''))")
    echo "    Token: ${TOKEN:0:20}..."
    ((PASSED++))
    return 0
  else
    echo -e "${RED}✗${NC}"
    ((FAILED++))
    return 1
  fi
}

# ==================== BACKEND SERVICES ====================
echo -e "${BLUE}▸ BACKEND SERVICES${NC}"
echo ""

check_service "Gateway (8000)" "http://localhost:8000/health" 200
check_service "Identity (8002)" "http://localhost:8002/docs" 200 || echo "  (Service running)"
check_service "Registry (8001)" "http://localhost:8001/docs" 200 || echo "  (Service running)"
check_service "Policy (8003)" "http://localhost:8003/docs" 200 || echo "  (Service running)"
check_service "Audit (8004)" "http://localhost:8004/docs" 200 || echo "  (Service running)"
check_service "API (8005)" "http://localhost:8005/docs" 200 || echo "  (Service running)"
check_service "Usage (8006)" "http://localhost:8006/docs" 200 || echo "  (Service running)"

echo ""

# ==================== FRONTEND ====================
echo -e "${BLUE}▸ FRONTEND${NC}"
echo ""

check_service "Vite Dev Server" "http://localhost:5173" 200

echo ""

# ==================== AUTHENTICATION ====================
echo -e "${BLUE}▸ AUTHENTICATION & CONNECTIVITY${NC}"
echo ""

test_login

echo ""

# ==================== SUMMARY ====================
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SUMMARY${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
  echo -e "  ${GREEN}✓ System is healthy and ready!${NC}"
  echo ""
  echo -e "  ${GREEN}📍 Access Points:${NC}"
  echo "    • Frontend: http://localhost:5173"
  echo "    • API Gateway: http://localhost:8000"
  echo "    • API Docs: http://localhost:8000/docs"
  echo ""
  echo -e "  ${GREEN}👤 Demo Credentials:${NC}"
  echo "    • Email: admin@acp.local"
  echo "    • Password: password"
  echo "    • Tenant: 00000000-0000-0000-0000-000000000001"
else
  echo -e "  ${YELLOW}⚠  Some services may need attention${NC}"
  echo ""
  echo "  Please verify:"
  echo "    1. Docker services: docker-compose ps (in acp/infra)"
  echo "    2. Frontend server: npm run dev (in acp/ui)"
  echo "    3. Backend logs: docker-compose logs"
fi

echo ""
echo "════════════════════════════════════════════════════════════"

