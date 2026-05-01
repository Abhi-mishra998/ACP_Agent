-- Create databases
CREATE DATABASE acp_registry;
CREATE DATABASE acp_identity;
CREATE DATABASE acp_audit;
CREATE DATABASE acp_api;
CREATE DATABASE acp_usage;

-- SECURITY: Passwords below are LOCAL DEV DEFAULTS ONLY.
-- For staging/production, rotate these via your secrets manager before deployment.
-- Each service user must have a distinct password. Generate with: openssl rand -hex 16
-- Update DATABASE_URL in docker-compose.yml/.env to match any changes here.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'registry_user') THEN
        CREATE USER registry_user WITH PASSWORD 'registry_dev_CHANGE_ME';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'identity_user') THEN
        CREATE USER identity_user WITH PASSWORD 'identity_dev_CHANGE_ME';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'audit_user') THEN
        CREATE USER audit_user WITH PASSWORD 'audit_dev_CHANGE_ME';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'api_user') THEN
        CREATE USER api_user WITH PASSWORD 'api_dev_CHANGE_ME';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'usage_user') THEN
        CREATE USER usage_user WITH PASSWORD 'usage_dev_CHANGE_ME';
    END IF;
END
$$;

-- Grant Database-level privileges
GRANT ALL PRIVILEGES ON DATABASE acp_registry TO registry_user;
GRANT ALL PRIVILEGES ON DATABASE acp_identity TO identity_user;
GRANT ALL PRIVILEGES ON DATABASE acp_audit TO audit_user;
GRANT ALL PRIVILEGES ON DATABASE acp_api TO api_user;
GRANT ALL PRIVILEGES ON DATABASE acp_usage TO usage_user;

-- Staff Engineer Fix: Grant Schema-level privileges (Required for Postgres 15+)
-- We must connect to each DB and grant these, but since this script runs on 'acp' or 'postgres' initial connection,
-- we'll use ALTER DEFAULT PRIVILEGES or ensure migrations can run.
-- The most reliable way in this init script is to ensure the users OWN the public schema in their respective DBs.

\c acp_registry
GRANT ALL ON SCHEMA public TO registry_user;
ALTER SCHEMA public OWNER TO registry_user;

\c acp_identity
GRANT ALL ON SCHEMA public TO identity_user;
ALTER SCHEMA public OWNER TO identity_user;

\c acp_audit
GRANT ALL ON SCHEMA public TO audit_user;
ALTER SCHEMA public OWNER TO audit_user;

\c acp_api
GRANT ALL ON SCHEMA public TO api_user;
ALTER SCHEMA public OWNER TO api_user;

\c acp_usage
GRANT ALL ON SCHEMA public TO usage_user;
ALTER SCHEMA public OWNER TO usage_user;
