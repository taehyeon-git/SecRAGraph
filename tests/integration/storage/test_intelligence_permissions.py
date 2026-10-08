"""Live PostgreSQL checks for the isolated security knowledge store."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from security_review.storage.intelligence import (
    IntelligenceImportError,
    PostgresSecurityKnowledgeRepository,
    import_intelligence_data,
)

pytestmark = pytest.mark.integration

_READER_ROLE = "secragraph_text2sql"


def database_url() -> str:
    return os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@localhost:55432/secragraph_test",
    )


def _alembic_config() -> Config:
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", database_url())
    return configuration


@pytest.fixture(scope="module")
def admin_engine() -> Iterator[Engine]:
    command.upgrade(_alembic_config(), "head")
    engine = create_engine(database_url(), pool_pre_ping=True)
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM intel.cve"))
        connection.execute(text("DELETE FROM intel.cwe"))
    import_intelligence_data(
        engine,
        Path("data/samples/cwe.csv"),
        Path("data/samples/cve.csv"),
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def reader_engine(admin_engine: Engine) -> Iterator[Engine]:
    reader_url = make_url(database_url()).set(
        username="secragraph_text2sql",
        password=os.getenv("SECRAGRAPH_TEST_READER_PASSWORD"),
    )
    engine = create_engine(reader_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


def _execute_as_reader(
    engine: Engine,
    sql: str,
    *,
    read_write: bool = False,
) -> list[tuple[object, ...]]:
    with engine.connect() as connection:
        if read_write:
            connection.execute(text("SET TRANSACTION READ WRITE"))
        return [tuple(row) for row in connection.execute(text(sql)).all()]


def test_text2sql_role_can_select_approved_intelligence_tables(reader_engine: Engine) -> None:
    assert _execute_as_reader(reader_engine, "SELECT cwe_id FROM intel.cwe LIMIT 1")
    assert _execute_as_reader(reader_engine, "SELECT cve_id FROM intel.cve LIMIT 1")
    assert _execute_as_reader(reader_engine, "SELECT current_user") == [("secragraph_text2sql",)]
    assert _execute_as_reader(
        reader_engine,
        "SELECT pg_has_role(current_user, 'secragraph_reader', 'member')",
    ) == [(True,)]


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO intel.cwe (cwe_id, name, description, source_url) "
        "VALUES ('CWE-9999', 'x', 'x', 'https://example.invalid')",
        "UPDATE intel.cwe SET name = 'changed' WHERE cwe_id = 'CWE-89'",
        "DELETE FROM intel.cwe WHERE cwe_id = 'CWE-89'",
        "TRUNCATE intel.cve",
        "CREATE TABLE intel.reader_escape (id integer)",
        "CREATE TEMP TABLE reader_escape (id integer)",
    ],
)
def test_text2sql_role_cannot_mutate_or_create(reader_engine: Engine, sql: str) -> None:
    with pytest.raises(DBAPIError):
        _execute_as_reader(reader_engine, sql, read_write=True)


def test_text2sql_role_cannot_read_application_reports(reader_engine: Engine) -> None:
    with pytest.raises(DBAPIError):
        _execute_as_reader(reader_engine, "SELECT target_name FROM app.scan_reports")


def test_old_default_grant_does_not_expose_future_application_tables(
    admin_engine: Engine,
    reader_engine: Engine,
) -> None:
    with admin_engine.begin() as connection:
        connection.execute(text("CREATE TABLE app.future_private (value text)"))
    try:
        with pytest.raises(DBAPIError):
            _execute_as_reader(reader_engine, "SELECT value FROM app.future_private")
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text("DROP TABLE app.future_private"))


def test_text2sql_role_cannot_read_an_unapproved_intelligence_table(
    admin_engine: Engine,
    reader_engine: Engine,
) -> None:
    with admin_engine.begin() as connection:
        connection.execute(text("CREATE TABLE intel.unapproved (value text)"))
    try:
        with pytest.raises(DBAPIError):
            _execute_as_reader(reader_engine, "SELECT value FROM intel.unapproved")
    finally:
        with admin_engine.begin() as connection:
            connection.execute(text("DROP TABLE intel.unapproved"))


def test_text2sql_login_applies_bounded_transaction_defaults(reader_engine: Engine) -> None:
    assert _execute_as_reader(reader_engine, "SHOW statement_timeout") == [("2s",)]
    assert _execute_as_reader(reader_engine, "SHOW default_transaction_read_only") == [("on",)]
    assert _execute_as_reader(
        reader_engine,
        "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
        "FROM pg_roles WHERE rolname = current_user",
    ) == [(False, False, False, False, False)]


def test_sample_import_updates_changed_rows_without_duplicates(
    admin_engine: Engine,
    tmp_path: Path,
) -> None:
    first = import_intelligence_data(
        admin_engine,
        Path("data/samples/cwe.csv"),
        Path("data/samples/cve.csv"),
    )
    changed_cwe = tmp_path / "cwe.csv"
    changed_cwe.write_text(
        Path("data/samples/cwe.csv")
        .read_text(encoding="utf-8")
        .replace("SQL command injection", "SQL injection updated by test"),
        encoding="utf-8",
    )
    try:
        second = import_intelligence_data(
            admin_engine,
            changed_cwe,
            Path("data/samples/cve.csv"),
        )

        with admin_engine.connect() as connection:
            cwe_count = connection.execute(text("SELECT count(*) FROM intel.cwe")).scalar_one()
            cve_count = connection.execute(text("SELECT count(*) FROM intel.cve")).scalar_one()
            changed_name = connection.execute(
                text("SELECT name FROM intel.cwe WHERE cwe_id = 'CWE-89'")
            ).scalar_one()

        assert first == second
        assert cwe_count == first.cwe_rows
        assert cve_count == first.cve_rows
        assert changed_name == "SQL injection updated by test"
    finally:
        import_intelligence_data(
            admin_engine,
            Path("data/samples/cwe.csv"),
            Path("data/samples/cve.csv"),
        )


def test_failed_cve_foreign_key_rolls_back_the_cwe_batch(
    admin_engine: Engine,
    tmp_path: Path,
) -> None:
    cwe_path = tmp_path / "cwe.csv"
    cwe_path.write_text(
        "cwe_id,name,description,source_url\n"
        "CWE-9998,Rollback probe,Must not survive,https://example.invalid/cwe/9998\n",
        encoding="utf-8",
    )
    cve_path = tmp_path / "cve.csv"
    cve_path.write_text(
        "cve_id,cwe_id,vendor,product,severity,cvss_score,published_at,summary,source_url\n"
        "CVE-2099-9998,CWE-9999,SecRAGraph Labs,Rollback,high,8.0,2099-01-04,"
        "Broken foreign key,https://example.invalid/cve/2099-9998\n",
        encoding="utf-8",
    )

    with pytest.raises(IntelligenceImportError, match="database import failed"):
        import_intelligence_data(admin_engine, cwe_path, cve_path)

    with admin_engine.connect() as connection:
        count = connection.execute(
            text("SELECT count(*) FROM intel.cwe WHERE cwe_id = 'CWE-9998'")
        ).scalar_one()
    assert count == 0


def test_repository_executes_through_the_distinct_reader_login(
    admin_engine: Engine,
    reader_engine: Engine,
) -> None:
    assert reader_engine.url.username == _READER_ROLE
    assert reader_engine.url.username != admin_engine.url.username
    repository = PostgresSecurityKnowledgeRepository(
        reader_engine.connect,
        row_limit=1,
        statement_timeout_ms=2_000,
    )

    result = repository.execute_readonly("SELECT cwe_id FROM intel.cwe ORDER BY cwe_id")

    assert result.columns == ("cwe_id",)
    assert len(result.rows) == 1


def test_upgrade_revokes_legacy_default_application_grants(
    admin_engine: Engine,
    reader_engine: Engine,
) -> None:
    configuration = _alembic_config()
    try:
        command.downgrade(configuration, "20260920_0001")
        with admin_engine.begin() as connection:
            connection.execute(text("GRANT USAGE ON SCHEMA app TO secragraph_reader"))
            connection.execute(
                text("GRANT SELECT ON ALL TABLES IN SCHEMA app TO secragraph_reader")
            )
            connection.execute(
                text(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA app "
                    "GRANT SELECT ON TABLES TO secragraph_reader"
                )
            )

        command.upgrade(configuration, "head")
        with admin_engine.begin() as connection:
            connection.execute(text("CREATE TABLE app.future_upgrade_probe (value text)"))

        with pytest.raises(DBAPIError):
            _execute_as_reader(reader_engine, "SELECT value FROM app.future_upgrade_probe")
    finally:
        command.upgrade(configuration, "head")
        with admin_engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS app.future_upgrade_probe"))
        import_intelligence_data(
            admin_engine,
            Path("data/samples/cwe.csv"),
            Path("data/samples/cve.csv"),
        )
