FROM alpine:3.20
RUN apk add --no-cache postgresql-client bash
CMD psql "host=${PGHOST} user=${PGUSER} dbname=${PGDATABASE} sslmode=${PGSSLMODE} sslrootcert=${PGSSLROOTCERT} sslcert=${PGSSLCERT} sslkey=${PGSSLKEY}" -c "select now();"