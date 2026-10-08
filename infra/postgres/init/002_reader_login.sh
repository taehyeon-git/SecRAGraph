#!/bin/sh
set -eu

: "${SECRAGRAPH_READER_PASSWORD:?SECRAGRAPH_READER_PASSWORD is required}"

psql \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    --set=ON_ERROR_STOP=1 \
    --set=database_name="$POSTGRES_DB" \
    --set=reader_password="$SECRAGRAPH_READER_PASSWORD" <<'SQL'
SELECT 'CREATE ROLE secragraph_reader NOLOGIN'
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'secragraph_reader'
)
\gexec

SELECT format(
    'CREATE ROLE secragraph_text2sql LOGIN INHERIT PASSWORD %L',
    :'reader_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'secragraph_text2sql'
)
\gexec

ALTER ROLE secragraph_text2sql PASSWORD :'reader_password';
ALTER ROLE secragraph_text2sql
    LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE secragraph_text2sql SET statement_timeout TO '2s';
ALTER ROLE secragraph_text2sql SET default_transaction_read_only TO 'on';
ALTER ROLE secragraph_reader
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE secragraph_reader SET statement_timeout TO '2s';
ALTER ROLE secragraph_reader SET default_transaction_read_only TO 'on';
GRANT secragraph_reader TO secragraph_text2sql;
GRANT CONNECT ON DATABASE :"database_name" TO secragraph_reader;
SQL
