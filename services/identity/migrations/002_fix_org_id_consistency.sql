-- =============================================================================
-- Migration: 002_fix_org_id_consistency
-- Database:  acp_identity
-- Purpose:   Safety-net backfill for users.org_id.
--            The Alembic migration f2b3c4d5e6a7 already does this during
--            upgrade, but this script is idempotent and safe to run on any
--            environment where Alembic was not applied (e.g. bare prod clones).
-- Run order: AFTER the column exists (added by f2b3c4d5e6a7 or init-db.sql).
-- =============================================================================

-- Step 1: Backfill NULLs — default org_id to the row's own tenant_id.
--         Any row without an explicit org must belong to its own tenant scope.
UPDATE users
SET org_id = tenant_id
WHERE org_id IS NULL;

-- Step 2: Harden the column — refuse future NULLs at the DB level.
--         This is a no-op if the NOT NULL constraint is already present.
ALTER TABLE users
    ALTER COLUMN org_id SET NOT NULL;

-- Step 3: Ensure the index exists for fast org-scoped queries.
CREATE INDEX IF NOT EXISTS ix_users_org_id ON users (org_id);
