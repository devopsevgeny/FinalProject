-- 12_grants_sequences.sql
-- Purpose: fix privileges for sequences used by bigserial in schema 'core'
-- Notes:
--   1) Grants cover existing sequences now.
--   2) Default privileges ensure future sequences are granted too.
--   3) Run at init time as 'postgres' (docker-entrypoint does this).

-- Existing sequences: allow the app role to use nextval()/currval()/setval()
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA core TO confmgr_db;

-- Future sequences created by the 'postgres' role in schema 'core'
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA core
GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO confmgr_db;

-- (Optional) If the app role ever creates sequences itself, future-proof that too
ALTER DEFAULT PRIVILEGES FOR ROLE confmgr_db IN SCHEMA core
GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO confmgr_db;
