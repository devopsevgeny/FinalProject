-- 10_core_schema.sql
-- Base schemas + CONFIG model + AUDIT parent table (no SECRET tables here)

-- Schemas
create schema if not exists core;
create schema if not exists audit;
create schema if not exists iam;

-- =========================
-- APPLICATION REGISTRY
-- =========================

create table if not exists core.apps(
  app_id     text primary key,
  app_name   text not null,
  created_at timestamptz not null default now(),
  is_active  boolean not null default true
);

create unique index if not exists ux_apps_name
  on core.apps(lower(app_name));

insert into core.apps(app_id, app_name)
values ('default', 'Default Application')
on conflict (app_id) do nothing;

-- =========================
-- CONFIG TABLES
-- =========================

create table if not exists core.config_items(
  id          bigserial primary key,
  app_id      text not null references core.apps(app_id),
  path        text not null,
  created_at  timestamptz not null default now(),
  created_by  uuid not null,
  is_deleted  boolean not null default false
);

create table if not exists core.config_versions(
  id          bigserial primary key,
  item_id     bigint not null references core.config_items(id) on delete cascade,
  version     int not null,
  is_current  boolean not null default true,
  data_type   text not null default 'json',
  value_json  jsonb,
  checksum    bytea not null,
  created_at  timestamptz not null default now(),
  created_by  uuid not null,
  constraint config_versions_data_type_ck
    check (data_type in ('json','file')),
  constraint config_versions_payload_ck
    check (
      (data_type = 'json' and value_json is not null) or
      (data_type = 'file' and value_json is null)
    )
);

-- Indexes for config
create index if not exists idx_config_items_app on core.config_items(app_id);
create unique index if not exists ux_config_items_app_path
  on core.config_items(app_id, path);
create unique index if not exists ux_config_versions_item_version
  on core.config_versions(item_id, version);
create unique index if not exists ux_config_versions_current
  on core.config_versions(item_id) where is_current;
create index if not exists idx_config_versions_value_json
  on core.config_versions using gin(value_json);
create index if not exists ix_config_item_ver_desc
  on core.config_versions(item_id, version desc);

create table if not exists core.config_version_files(
  version_id   bigint primary key references core.config_versions(id) on delete cascade,
  file_name    text not null,
  content_type text not null,
  file_size    bigint not null check (file_size >= 0),
  file_data    bytea not null
);

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

grant select, insert, update on core.apps to confmgr_db;
grant select on core.config_items to confmgr_db;
grant select, insert, update on core.config_versions to confmgr_db;
grant select, insert, update on core.config_version_files to confmgr_db;

grant insert on audit.audit_logs to confmgr_db;
