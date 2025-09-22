#!/usr/bin/env bash

set -euo pipefail

echo "[entrypoint] listing /certs:"; ls -l /certs || true

# Copy TLS and change 
if [[ -f /certs/server.crt && -f /certs/server.key && -f /certs/ca.crt ]]; then
  cp /certs/server.crt /var/lib/postgresql/server.crt
  cp /certs/server.key /var/lib/postgresql/server.key
  cp /certs/ca.crt     /var/lib/postgresql/ca.crt
  chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key /var/lib/postgresql/ca.crt
  chmod 600 /var/lib/postgresql/server.key
  chmod 644 /var/lib/postgresql/server.crt /var/lib/postgresql/ca.crt
  echo "[entrypoint] certs copied."
else
  echo "[entrypoint] ERROR: missing {server.crt, server.key, ca.crt}"; exit 1
fi

# Run entrypoint as user postgres
exec gosu postgres /usr/local/bin/docker-entrypoint.sh postgres \
  -c config_file=/etc/postgresql/postgresql.conf \
  -c hba_file=/etc/postgresql/pg_hba.conf \
  -c ident_file=/etc/postgresql/pg_ident.conf
