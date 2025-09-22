create role confmgr_db login;
alter role confmgr_db set search_path = core,iam,audit,public;
grant usage on schema public to confmgr_db;