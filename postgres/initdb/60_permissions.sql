-- 60_permissions.sql
-- Purpose: grant all runtime privileges needed by app role (confmgr_db).
-- Safe to run multiple times; idempotent enough for GRANT/ALTER DEFAULT PRIVILEGES.

-- ===== Schemas =====
GRANT USAGE ON SCHEMA core  TO confmgr_db;
GRANT USAGE ON SCHEMA audit TO confmgr_db;
GRANT USAGE ON SCHEMA iam   TO confmgr_db;

-- ===== Tables (existing) =====
-- App needs to insert/select/update items and versions; it also reads api_clients.
GRANT SELECT, INSERT, UPDATE ON TABLE core.secret_items     TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.secret_versions  TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.config_items     TO confmgr_db;
GRANT SELECT, INSERT, UPDATE ON TABLE core.config_versions  TO confmgr_db;
GRANT SELECT                      ON TABLE core.api_clients TO confmgr_db;

-- ===== Auth grants (login) =====
-- Read users + roles for /auth/login:
GRANT SELECT ON core.users, core.roles, core.user_roles TO confmgr_db;
-- Update only the last_login column:
GRANT UPDATE (last_login) ON core.users TO confmgr_db;

-- ===== Sequences (existing) =====
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core TO confmgr_db;

-- ===== Default privileges (future objects) =====
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA core
  GRANT SELECT, INSERT, UPDATE ON TABLES TO confmgr_db;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA core
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO confmgr_db;
