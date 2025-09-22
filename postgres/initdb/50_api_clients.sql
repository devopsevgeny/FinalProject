-- Enable pgcrypto for password hashing
create extension if not exists pgcrypto;

-- API clients registry
create table if not exists core.api_clients (
  id          uuid primary key default gen_random_uuid(),
  client_id   text unique not null,
  -- store a salted hash, not the raw secret (bcrypt via pgcrypto)
  client_secret_hash text not null,
  issuer      text,
  is_active   boolean not null default true,
  created_at  timestamptz not null default now()
);

create unique index if not exists ux_api_clients_client_id
  on core.api_clients(client_id);

-- Minimal privileges for the app
grant usage on schema core to confmgr_db;
grant select on core.api_clients to confmgr_db;

