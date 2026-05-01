-- Migration: Add composite index on users(email, tenant_id)
-- Purpose: Optimize login queries that filter by both email and tenant_id
-- Impact: Improves query performance for multi-tenant user lookups

CREATE INDEX IF NOT EXISTS idx_users_email_tenant 
ON users(email, tenant_id);

-- Optional: Add index on (tenant_id, email) for reverse lookup patterns
-- Uncomment if needed for other query patterns
-- CREATE INDEX IF NOT EXISTS idx_users_tenant_email 
-- ON users(tenant_id, email);
