-- 60_permissions.sql
-- Purpose: grant all runtime privileges needed by app role (confmgr_db).
-- Safe to run multiple times; idempotent enough for GRANT/ALTER DEFAULT PRIVILEGES.

-- ===== Schemas =====
GRANT USAGE ON SCHEMA core TO confmgr_db;
GRANT USAGE ON SCHEMA audit TO confmgr_db;
GRANT USAGE ON SCHEMA iam   TO confmgr_db;

-- ===== Tables (existing) =====
-- App needs to insert/select/update items and versions; it also reads api_clients.
GRANT SELECT, INSERT, UPDATE ON TABLE core.secret_items     TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.secret_versions  TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.config_items     TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.config_versions  TO confmgr_db;
GRANT SELECT                      ON TABLE core.api_clients TO confmgr_db;

-- ===== Sequences (existing) =====
-- SELECT/USAGE/UPDATE on sequences is required for bigserial/serial nextval/currval
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core TO confmgr_db;

-- ===== Default privileges (future objects) =====
-- Ensure that any future tables/sequences created by 'postgres' in schema core
-- will automatically grant the same privileges to confmgr_db.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA core
  GRANT SELECT, INSERT, UPDATE ON TABLES TO confmgr_db;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA core
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO confmgr_db;
