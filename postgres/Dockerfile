FROM postgres:16

# Copy configuration and bootstrap SQL scripts
COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY pg_hba.conf /etc/postgresql/pg_hba.conf
COPY pg_ident.conf /etc/postgresql/pg_ident.conf
COPY initdb/ /docker-entrypoint-initdb.d/

# Custom entrypoint copies TLS certs then defers to the stock entrypoint
COPY entrypoint.sh /confmgr-entrypoint.sh
RUN chmod +x /confmgr-entrypoint.sh

ENTRYPOINT ["/confmgr-entrypoint.sh"]
