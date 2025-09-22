-- 40_secret_crypto.sql
-- SECRET tables + trigger + indexes + grants (no overlap with 10_core_schema.sql)

create schema if not exists core;

-- Items
create table if not exists core.secret_items(
  id          bigserial primary key,
  path        text not null unique,
  created_by  uuid not null,
  created_at  timestamptz not null default now()
);

-- Versions
create table if not exists core.secret_versions(
  item_id     bigint not null references core.secret_items(id) on delete cascade,
  version     int not null,
  is_current  boolean not null default true,
  ciphertext  bytea not null,
  nonce       bytea not null,
  alg         text  not null,
  created_by  uuid  not null,
  created_at  timestamptz not null default now(),
  primary key (item_id, version),
  constraint secret_alg_ck check (alg in ('AES256-GCM'))
);

-- Indexes for fast lookups
create index if not exists idx_secret_items_path on core.secret_items(path);
create unique index if not exists ux_secret_versions_current
  on core.secret_versions(item_id) where is_current;
create index if not exists ix_secret_item_ver_desc
  on core.secret_versions(item_id, version desc);

-- Trigger function: auto version bump + keep only one current
create or replace function core.fn_secret_versions_bi()
returns trigger language plpgsql as $$
begin
  if new.version is null then
    select coalesce(max(version), 0) + 1
      into new.version
      from core.secret_versions
     where item_id = new.item_id;
  end if;

  if new.is_current then
    update core.secret_versions
       set is_current = false
     where item_id = new.item_id
       and is_current = true;
  end if;

  return new;
end
$$;

drop trigger if exists trg_secret_versions_bi on core.secret_versions;
create trigger trg_secret_versions_bi
before insert on core.secret_versions
for each row execute function core.fn_secret_versions_bi();

-- Minimal privileges for the app role
grant usage on schema core to confmgr_db;
grant select, insert on core.secret_items to confmgr_db;
grant select, insert, update on core.secret_versions to confmgr_db;
