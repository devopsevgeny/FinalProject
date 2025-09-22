-- 10_core_schema.sql
-- Base schemas + CONFIG model + AUDIT parent table (no SECRET tables here)

-- Schemas
create schema if not exists core;
create schema if not exists audit;
create schema if not exists iam;

-- =========================
-- CONFIG TABLES
-- =========================

create table if not exists core.config_items(
  id          bigserial primary key,
  path        text not null unique,
  created_at  timestamptz not null default now(),
  created_by  uuid not null,
  is_deleted  boolean not null default false
);

create table if not exists core.config_versions(
  id          bigserial primary key,
  item_id     bigint not null references core.config_items(id) on delete cascade,
  version     int not null,
  is_current  boolean not null default true,
  value_json  jsonb not null,
  checksum    bytea not null,
  created_at  timestamptz not null default now(),
  created_by  uuid not null
);

-- Indexes for config
create index if not exists idx_config_items_path on core.config_items(path);
create unique index if not exists ux_config_versions_item_version
  on core.config_versions(item_id, version);
create unique index if not exists ux_config_versions_current
  on core.config_versions(item_id) where is_current;
create index if not exists idx_config_versions_value_json
  on core.config_versions using gin(value_json);
create index if not exists ix_config_item_ver_desc
  on core.config_versions(item_id, version desc);

-- Trigger function: auto version bump + keep only one current
create or replace function core.fn_config_versions_bi()
returns trigger language plpgsql as $$
begin
  if new.version is null then
    select coalesce(max(version), 0) + 1
      into new.version
      from core.config_versions
     where item_id = new.item_id;
  end if;

  if new.is_current then
    update core.config_versions
       set is_current = false
     where item_id = new.item_id
       and is_current = true;
  end if;

  return new;
end
$$;

drop trigger if exists trg_config_versions_bi on core.config_versions;
create trigger trg_config_versions_bi
before insert on core.config_versions
for each row execute function core.fn_config_versions_bi();

-- =========================
-- AUDIT (partitioned parent)
-- =========================

create table if not exists audit.audit_logs(
  id           bigserial,
  created_at   timestamptz not null default now(),
  actor_id     uuid not null,
  actor_subject text not null,
  action       text not null,
  path         text not null,
  client_ip    inet,
  mfa          boolean,
  extra        jsonb not null default '{}'::jsonb,
  primary key (id, created_at)
) partition by range (created_at);

-- =========================
-- GRANTS (assumes role 'confmgr_db' exists from 00_roles.sql)
-- =========================

grant usage on schema core, audit, iam to confmgr_db;

grant select on core.config_items to confmgr_db;
grant select, insert, update on core.config_versions to confmgr_db;

grant insert on audit.audit_logs to confmgr_db;
