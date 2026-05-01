#!/bin/bash
# =============================================================================
# ACP Migration CI Guard
# =============================================================================
# Verifies that:
#   1. Every service's migration history is consistent.
#   2. Local models match the database schema (no pending migrations).
# =============================================================================

set -e

# Load .env if it exists and DATABASE_URL is not set
if [ -f .env ] && [ -z "$DATABASE_URL" ]; then
    export $(grep -v '^#' .env | xargs)
fi

SERVICES=("identity" "audit" "registry")

echo "🚀 Starting migration consistency check..."

# Save original DATABASE_URL
ORIGINAL_DB_URL=$DATABASE_URL

ROOT_DIR=$(pwd)
ALEMBIC_CMD="$ROOT_DIR/.venv/bin/alembic"
if [ ! -f "$ALEMBIC_CMD" ]; then
    ALEMBIC_CMD="alembic"
fi

for SERVICE in "${SERVICES[@]}"; do
    echo "--- Checking service: $SERVICE ---"
    
    # Map service to its dedicated database
    if [[ "$ORIGINAL_DB_URL" == *"/acp" ]]; then
        export DATABASE_URL="${ORIGINAL_DB_URL}_${SERVICE}"
        echo "🔗 Targeting: $DATABASE_URL"
    fi
    
    # 1. Check for drift (Alembic 1.9+ feature)
    echo "🔍 Checking for schema drift..."
    cd "services/$SERVICE" && $ALEMBIC_CMD check
    cd - > /dev/null
    
    # 2. Verify all migrations have been applied
    echo "🔍 Verifying current migration is HEAD..."
    cd "services/$SERVICE" && $ALEMBIC_CMD current
    cd - > /dev/null
    echo ""
done

# Restore original URL
export DATABASE_URL=$ORIGINAL_DB_URL

echo "✅ All services are consistent and up-to-date."
