"""Tests for validated intelligence imports and bounded SQL results."""

from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.elements import TextClause

from security_review.storage.intelligence import (
    IntelligenceImportError,
    PostgresSecurityKnowledgeRepository,
    import_intelligence_data,
    intelligence_metadata,
    load_cve_rows,
    load_cwe_rows,
)


class FakeResult:
    def __init__(self, columns: tuple[str, ...] = (), rows: tuple[tuple[Any, ...], ...] = ()):
        self._columns = columns
        self._rows = rows

    def keys(self) -> tuple[str, ...]:
        return self._columns

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return list(self._rows[:size])


class FakeConnection:
    def __init__(self, query_result: FakeResult) -> None:
        self.query_result = query_result
        self.executed: list[tuple[str, dict[str, Any] | None]] = []

    def execute(
        self,
        statement: TextClause,
        parameters: dict[str, Any] | None = None,
    ) -> FakeResult:
        sql = str(statement)
        self.executed.append((sql, parameters))
        if sql == "SELECT cwe_id FROM intel.cwe":
            return self.query_result
        return FakeResult()


class FakeConnectionContext(AbstractContextManager[FakeConnection]):
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def __enter__(self) -> FakeConnection:
        return self.connection

    def __exit__(self, *args: object) -> None:
        return None


class FakeImportConnection:
    def __init__(self) -> None:
        self.statements: list[Any] = []

    def execute(self, statement: Any) -> None:
        self.statements.append(statement)


class FakeImportTransaction(AbstractContextManager[FakeImportConnection]):
    def __init__(self, connection: FakeImportConnection) -> None:
        self.connection = connection

    def __enter__(self) -> FakeImportConnection:
        return self.connection

    def __exit__(self, *args: object) -> None:
        return None


class FakeImportEngine:
    def __init__(self) -> None:
        self.connection = FakeImportConnection()
        self.begin_calls = 0

    def begin(self) -> FakeImportTransaction:
        self.begin_calls += 1
        return FakeImportTransaction(self.connection)


def test_repository_caps_rows_and_sets_defensive_transaction_controls() -> None:
    connection = FakeConnection(
        FakeResult(
            ("cwe_id",),
            (("CWE-79",), ("CWE-89",), ("CWE-95",)),
        )
    )
    repository = PostgresSecurityKnowledgeRepository(
        lambda: FakeConnectionContext(connection),
        row_limit=2,
        statement_timeout_ms=1_250,
    )

    result = repository.execute_readonly("SELECT cwe_id FROM intel.cwe")

    assert result.columns == ("cwe_id",)
    assert result.rows == (("CWE-79",), ("CWE-89",))
    assert connection.executed == [
        ("SET TRANSACTION READ ONLY", None),
        (
            "SELECT set_config('statement_timeout', :timeout, true)",
            {"timeout": "1250ms"},
        ),
        ("SELECT cwe_id FROM intel.cwe", None),
    ]


def test_alembic_tracks_both_intelligence_tables_and_their_indexes() -> None:
    assert set(intelligence_metadata.tables) == {"intel.cwe", "intel.cve"}
    assert {index.name for index in intelligence_metadata.tables["intel.cve"].indexes} == {
        "ix_cve_cwe_id",
        "ix_cve_vendor",
    }
    assert "updated_at" in intelligence_metadata.tables["intel.cwe"].c


def test_repository_normalizes_database_scalars_for_json_safe_results() -> None:
    connection = FakeConnection(
        FakeResult(
            ("score", "published", "updated"),
            (
                (
                    Decimal("8.2"),
                    date(2099, 1, 2),
                    datetime(2099, 1, 2, 3, 4, tzinfo=UTC),
                ),
            ),
        )
    )
    repository = PostgresSecurityKnowledgeRepository(
        lambda: FakeConnectionContext(connection),
        row_limit=5,
        statement_timeout_ms=2_000,
    )

    result = repository.execute_readonly("SELECT cwe_id FROM intel.cwe")

    assert result.rows == ((8.2, "2099-01-02", "2099-01-02T03:04:00+00:00"),)


def test_loads_valid_cwe_and_cve_rows(tmp_path: Path) -> None:
    cwe_path = tmp_path / "cwe.csv"
    cwe_path.write_text(
        "cwe_id,name,description,source_url\n"
        "CWE-89,SQL command injection,Untrusted input changes a query,"
        "https://example.invalid/cwe/89\n",
        encoding="utf-8",
    )
    cve_path = tmp_path / "cve.csv"
    cve_path.write_text(
        "cve_id,cwe_id,vendor,product,severity,cvss_score,published_at,summary,source_url\n"
        "CVE-2099-0001,CWE-89,SecRAGraph Labs,Demo API,high,8.2,2099-01-02,"
        "Synthetic training record,https://example.invalid/cve/2099-0001\n",
        encoding="utf-8",
    )

    cwes = load_cwe_rows(cwe_path)
    cves = load_cve_rows(cve_path)

    assert cwes[0].cwe_id == "CWE-89"
    assert str(cwes[0].source_url) == "https://example.invalid/cwe/89"
    assert cves[0].cvss_score == 8.2
    assert cves[0].published_at == date(2099, 1, 2)


def test_csv_validation_reports_the_source_line_without_echoing_record(tmp_path: Path) -> None:
    path = tmp_path / "cwe.csv"
    path.write_text(
        "cwe_id,name,description,source_url\n"
        "not-a-cwe,Bad row,Do not echo this sensitive description,not-a-url\n",
        encoding="utf-8",
    )

    with pytest.raises(IntelligenceImportError, match=r"cwe\.csv:2: invalid CWE row") as captured:
        load_cwe_rows(path)

    assert "sensitive description" not in str(captured.value)


def test_csv_validation_rejects_duplicate_headers_and_identifiers(tmp_path: Path) -> None:
    duplicate_header = tmp_path / "duplicate-header.csv"
    duplicate_header.write_text(
        "cwe_id,name,name,description,source_url\n",
        encoding="utf-8",
    )
    with pytest.raises(IntelligenceImportError, match="duplicate CWE header"):
        load_cwe_rows(duplicate_header)

    duplicate_id = tmp_path / "duplicate-id.csv"
    duplicate_id.write_text(
        "cwe_id,name,description,source_url\n"
        "CWE-89,First,First description,https://example.invalid/first\n"
        "CWE-89,Second,Second description,https://example.invalid/second\n",
        encoding="utf-8",
    )
    with pytest.raises(IntelligenceImportError, match=r":3: duplicate CWE identifier"):
        load_cwe_rows(duplicate_id)


def test_large_imports_are_batched_inside_one_transaction(tmp_path: Path) -> None:
    cwe_path = tmp_path / "cwe.csv"
    cwe_path.write_text(
        "cwe_id,name,description,source_url\n"
        "CWE-89,SQL injection,Training row,https://example.invalid/cwe/89\n",
        encoding="utf-8",
    )
    cve_path = tmp_path / "cve.csv"
    cve_rows = "".join(
        f"CVE-2099-{index + 1000:04d},CWE-89,Vendor,Product,high,8.0,2099-01-02,"
        f"Synthetic row {index},https://example.invalid/cve/{index}\n"
        for index in range(1_001)
    )
    cve_path.write_text(
        "cve_id,cwe_id,vendor,product,severity,cvss_score,published_at,summary,source_url\n"
        + cve_rows,
        encoding="utf-8",
    )
    engine = FakeImportEngine()

    summary = import_intelligence_data(  # type: ignore[arg-type]
        engine,
        cwe_path,
        cve_path,
    )

    assert summary.cve_rows == 1_001
    assert engine.begin_calls == 1
    assert [statement.table.name for statement in engine.connection.statements] == [
        "cwe",
        "cve",
        "cve",
    ]
    assert all(
        len(statement.compile(dialect=postgresql.dialect()).params) < 65_535
        for statement in engine.connection.statements
    )
