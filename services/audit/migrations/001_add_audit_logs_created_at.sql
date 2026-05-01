-- =============================================================================
-- Migration: 001_add_audit_logs_created_at
-- Database:  acp_audit
-- Purpose:   Add the missing created_at column to audit_logs if absent.
--            Uses IF NOT EXISTS so the statement is fully idempotent.
-- =============================================================================

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT now();
