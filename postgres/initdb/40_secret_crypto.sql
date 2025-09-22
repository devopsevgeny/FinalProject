-- Schemas (create if not exists)
create schema if not exists core;
create schema if not exists audit;

-- Secret items + versions (similar to config)
create table if not exists core.secret_items(
  id bigserial primary key,
  path text unique not null,
  created_by uuid not null,
  created_at timestamptz not null default now()
);

create table if not exists core.secret_versions(
  item_id bigint not null references core.secret_items(id) on delete cascade,
  version int not null,
  is_current boolean not null default true,
  ciphertext bytea not null,
  nonce bytea not null,
  alg text not null, -- e.g. 'AES256-GCM'
  created_by uuid not null,
  created_at timestamptz not null default now(),
  primary key(item_id, version)
);

-- Auto-increment version + ensure only one current version
create or replace function core.fn_secret_versions_bi()
returns trigger language plpgsql as $$
begin
  if NEW.version is null then
    select coalesce(max(version), 0)+1 into NEW.version
    from core.secret_versions where item_id = NEW.item_id;
  end if;
  if NEW.is_current then
    update core.secret_versions set is_current = false
    where item_id = NEW.item_id and version <> NEW.version;
  end if;
  return NEW;
end$$;

drop trigger if exists trg_secret_versions_bi on core.secret_versions;
create trigger trg_secret_versions_bi
before insert on core.secret_versions
for each row execute function core.fn_secret_versions_bi();

-- Minimal privileges
grant usage on schema core to confmgr_db;
grant select, insert on core.secret_items to confmgr_db;
grant select, insert on core.secret_versions to confmgr_db;

