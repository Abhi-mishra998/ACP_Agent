-- =============================================================================
-- Migration: 001_add_agents_risk_level
-- Database:  acp_registry
-- Purpose:   Add the missing risk_level column to agents if absent.
--            Defaults to 'low' so existing rows satisfy any NOT NULL check.
--            Uses IF NOT EXISTS so the statement is fully idempotent.
-- =============================================================================

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS risk_level VARCHAR(50) DEFAULT 'low';
