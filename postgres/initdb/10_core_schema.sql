create schema if not exists core;
create schema if not exists audit;
create schema if not exists iam;

create table if not exists core.secret_items(
  id bigserial primary key,
  path text not null unique,
  type text not null,
  created_at timestamptz not null default now(),
  created_by uuid not null,
  is_deleted boolean not null default false
);

create table if not exists core.secret_versions(
  id bigserial primary key,
  item_id bigint not null references core.secret_items(id) on delete restrict,
  version int not null,
  is_current boolean not null default true,
  ciphertext bytea not null,
  dek_encrypted bytea not null,
  aad bytea not null,
  algo text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  created_by uuid not null
);

create table if not exists core.config_items(
  id bigserial primary key,
  path text not null unique,
  created_at timestamptz not null default now(),
  created_by uuid not null,
  is_deleted boolean not null default false
);

create table if not exists core.config_versions(
  id bigserial primary key,
  item_id bigint not null references core.config_items(id) on delete restrict,
  version int not null,
  is_current boolean not null default true,
  value_json jsonb not null,
  checksum bytea not null,
  created_at timestamptz not null default now(),
  created_by uuid not null
);

create index if not exists idx_secret_items_path on core.secret_items(path);
create unique index if not exists ux_secret_versions_item_version on core.secret_versions(item_id, version);
create unique index if not exists ux_secret_versions_current on core.secret_versions(item_id) where is_current;
create index if not exists idx_config_items_path on core.config_items(path);
create unique index if not exists ux_config_versions_item_version on core.config_versions(item_id, version);
create unique index if not exists ux_config_versions_current on core.config_versions(item_id) where is_current;
create index if not exists idx_config_versions_value_json on core.config_versions using gin(value_json);

create or replace function core.bump_version_and_flip_current()
returns trigger language plpgsql as $$
begin
  if new.version is null then
    select coalesce(max(version),0)+1 into new.version
    from core.secret_versions where item_id = new.item_id;
  end if;
  if new.is_current then
    update core.secret_versions set is_current = false
    where item_id = new.item_id and is_current = true;
  end if;
  return new;
end$$;

create or replace function core.bump_version_and_flip_current_cfg()
returns trigger language plpgsql as $$
begin
  if new.version is null then
    select coalesce(max(version),0)+1 into new.version
    from core.config_versions where item_id = new.item_id;
  end if;
  if new.is_current then
    update core.config_versions set is_current = false
    where item_id = new.item_id and is_current = true;
  end if;
  return new;
end$$;

drop trigger if exists trg_secret_versions_bi on core.secret_versions;
create trigger trg_secret_versions_bi
before insert on core.secret_versions
for each row execute function core.bump_version_and_flip_current();

drop trigger if exists trg_config_versions_bi on core.config_versions;
create trigger trg_config_versions_bi
before insert on core.config_versions
for each row execute function core.bump_version_and_flip_current_cfg();

grant usage on schema core, audit, iam to confmgr_db;
grant select on core.secret_items, core.config_items to confmgr_db;
grant select, insert, update on core.secret_versions, core.config_versions to confmgr_db;

create table if not exists audit.audit_logs(
  id bigserial,
  created_at timestamptz not null default now(),
  actor_id uuid not null,
  actor_subject text not null,
  action text not null,
  path text not null,
  client_ip inet,
  mfa boolean,
  extra jsonb not null default '{}'::jsonb,
  primary key (id, created_at)
) partition by range (created_at);

grant insert on audit.audit_logs to confmgr_db;