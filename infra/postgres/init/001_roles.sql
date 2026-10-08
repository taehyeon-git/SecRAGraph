-- Local bootstrap: the database owner comes from POSTGRES_USER.
-- The reader is NOLOGIN so deployments can grant it to an externally managed login.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secragraph_reader') THEN
        CREATE ROLE secragraph_reader NOLOGIN;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA app FROM secragraph_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA app
    REVOKE SELECT ON TABLES FROM secragraph_reader;

ALTER ROLE secragraph_reader SET statement_timeout TO '2s';
ALTER ROLE secragraph_reader SET default_transaction_read_only TO 'on';

DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO secragraph_reader',
        current_database()
    );
    EXECUTE format(
        'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );
END
$$;
