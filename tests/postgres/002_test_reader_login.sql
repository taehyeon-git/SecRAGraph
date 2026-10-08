-- The loopback-only test database uses trust authentication and no password.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secragraph_text2sql') THEN
        CREATE ROLE secragraph_text2sql LOGIN INHERIT;
    END IF;
END
$$;

ALTER ROLE secragraph_text2sql
    LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE secragraph_text2sql SET statement_timeout TO '2s';
ALTER ROLE secragraph_text2sql SET default_transaction_read_only TO 'on';
GRANT secragraph_reader TO secragraph_text2sql;
