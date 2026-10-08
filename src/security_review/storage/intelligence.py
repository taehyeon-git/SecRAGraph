"""Validated imports and bounded PostgreSQL access for security intelligence."""

from __future__ import annotations

import csv
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError, field_validator
from sqlalchemy import (
    CheckConstraint,
    Column,
    Connection,
    Date,
    DateTime,
    Engine,
    ForeignKey,
    Index,
    MetaData,
    Numeric,
    String,
    Table,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from security_review.intelligence.models import QueryResult, QueryScalar
from security_review.ports import IntelligenceUnavailableError

_CWE_ID = r"^CWE-\d+$"
_CVE_ID = r"^CVE-\d{4}-\d{4,}$"
_IMPORT_BATCH_SIZE = 1_000

intelligence_metadata = MetaData(schema="intel")
CWE_TABLE = Table(
    "cwe",
    intelligence_metadata,
    Column("cwe_id", String(20), primary_key=True),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=False),
    Column("source_url", Text, nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    CheckConstraint("cwe_id ~ '^CWE-[0-9]+$'", name="ck_cwe_identifier"),
)
CVE_TABLE = Table(
    "cve",
    intelligence_metadata,
    Column("cve_id", String(32), primary_key=True),
    Column(
        "cwe_id",
        String(20),
        ForeignKey("intel.cwe.cwe_id", name="fk_cve_cwe_id_cwe", ondelete="SET NULL"),
        nullable=True,
    ),
    Column("vendor", String(255), nullable=False),
    Column("product", String(255), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("cvss_score", Numeric(3, 1), nullable=False),
    Column("published_at", Date, nullable=False),
    Column("summary", Text, nullable=False),
    Column("source_url", Text, nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    CheckConstraint("cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name="ck_cve_identifier"),
    CheckConstraint(
        "severity IN ('low', 'medium', 'high', 'critical')",
        name="ck_cve_severity",
    ),
    CheckConstraint("cvss_score >= 0 AND cvss_score <= 10", name="ck_cve_cvss_score"),
)
Index("ix_cve_cwe_id", CVE_TABLE.c.cwe_id)
Index("ix_cve_vendor", CVE_TABLE.c.vendor)


class IntelligenceImportError(ValueError):
    """A safe, record-free error raised for invalid import input or storage failure."""


class _ImportRow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


class CweImportRow(_ImportRow):
    """One validated row in SecRAGraph's documented CWE import format."""

    cwe_id: str = Field(pattern=_CWE_ID, max_length=20)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    source_url: HttpUrl


class CveImportRow(_ImportRow):
    """One validated row in SecRAGraph's documented CVE import format."""

    cve_id: str = Field(pattern=_CVE_ID, max_length=32)
    cwe_id: Annotated[str, Field(pattern=_CWE_ID, max_length=20)] | None
    vendor: str = Field(min_length=1, max_length=255)
    product: str = Field(min_length=1, max_length=255)
    severity: Literal["low", "medium", "high", "critical"]
    cvss_score: float = Field(ge=0, le=10)
    published_at: date
    summary: str = Field(min_length=1)
    source_url: HttpUrl

    @field_validator("cwe_id", mode="before")
    @classmethod
    def blank_cwe_is_none(cls, value: object) -> object:
        return None if value == "" else value


class ImportSummary(BaseModel):
    """Stable import counts; repeated imports return the same values."""

    model_config = ConfigDict(frozen=True)

    cwe_rows: int = Field(ge=0)
    cve_rows: int = Field(ge=0)


Row = TypeVar("Row", bound=_ImportRow)


def _load_rows(
    path: Path,
    model: type[Row],
    label: str,
    identifier_field: str,
) -> tuple[Row, ...]:
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)):
                raise IntelligenceImportError(f"{path}: duplicate {label} header")
            expected = set(model.model_fields)
            actual = set(headers)
            if actual != expected:
                missing = ", ".join(sorted(expected - actual)) or "none"
                unexpected = ", ".join(sorted(actual - expected)) or "none"
                raise IntelligenceImportError(
                    f"{path}: invalid {label} header (missing: {missing}; unexpected: {unexpected})"
                )
            rows: list[Row] = []
            first_seen: dict[str, int] = {}
            for record in reader:
                try:
                    row = model.model_validate(record)
                except ValidationError as error:
                    raise IntelligenceImportError(
                        f"{path}:{reader.line_num}: invalid {label} row"
                    ) from error
                identifier = str(getattr(row, identifier_field))
                if identifier in first_seen:
                    raise IntelligenceImportError(
                        f"{path}:{reader.line_num}: duplicate {label} identifier "
                        f"(first seen at line {first_seen[identifier]})"
                    )
                first_seen[identifier] = reader.line_num
                rows.append(row)
            return tuple(rows)
    except (csv.Error, OSError, UnicodeError) as error:
        raise IntelligenceImportError(f"could not read {label} CSV: {path}") from error


def load_cwe_rows(path: Path) -> tuple[CweImportRow, ...]:
    return _load_rows(path, CweImportRow, "CWE", "cwe_id")


def load_cve_rows(path: Path) -> tuple[CveImportRow, ...]:
    return _load_rows(path, CveImportRow, "CVE", "cve_id")


def _cwe_values(rows: Sequence[CweImportRow]) -> list[dict[str, Any]]:
    return [
        {
            "cwe_id": row.cwe_id,
            "name": row.name,
            "description": row.description,
            "source_url": str(row.source_url),
        }
        for row in rows
    ]


def _cve_values(rows: Sequence[CveImportRow]) -> list[dict[str, Any]]:
    return [
        {
            "cve_id": row.cve_id,
            "cwe_id": row.cwe_id,
            "vendor": row.vendor,
            "product": row.product,
            "severity": row.severity,
            "cvss_score": row.cvss_score,
            "published_at": row.published_at,
            "summary": row.summary,
            "source_url": str(row.source_url),
        }
        for row in rows
    ]


def _batches(rows: Sequence[Row], size: int = _IMPORT_BATCH_SIZE) -> Iterator[Sequence[Row]]:
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


def import_intelligence_data(
    engine: Engine,
    cwe_path: Path,
    cve_path: Path,
) -> ImportSummary:
    """Validate both files first, then atomically upsert their rows."""

    cwe_rows = load_cwe_rows(cwe_path)
    cve_rows = load_cve_rows(cve_path)
    try:
        with engine.begin() as connection:
            for cwe_batch in _batches(cwe_rows):
                cwe_insert = insert(CWE_TABLE).values(_cwe_values(cwe_batch))
                connection.execute(
                    cwe_insert.on_conflict_do_update(
                        index_elements=[CWE_TABLE.c.cwe_id],
                        set_={
                            "name": cwe_insert.excluded.name,
                            "description": cwe_insert.excluded.description,
                            "source_url": cwe_insert.excluded.source_url,
                            "updated_at": func.now(),
                        },
                    )
                )
            for cve_batch in _batches(cve_rows):
                cve_insert = insert(CVE_TABLE).values(_cve_values(cve_batch))
                connection.execute(
                    cve_insert.on_conflict_do_update(
                        index_elements=[CVE_TABLE.c.cve_id],
                        set_={
                            "cwe_id": cve_insert.excluded.cwe_id,
                            "vendor": cve_insert.excluded.vendor,
                            "product": cve_insert.excluded.product,
                            "severity": cve_insert.excluded.severity,
                            "cvss_score": cve_insert.excluded.cvss_score,
                            "published_at": cve_insert.excluded.published_at,
                            "summary": cve_insert.excluded.summary,
                            "source_url": cve_insert.excluded.source_url,
                            "updated_at": func.now(),
                        },
                    )
                )
    except SQLAlchemyError as error:
        raise IntelligenceImportError("security intelligence database import failed") from error
    return ImportSummary(cwe_rows=len(cwe_rows), cve_rows=len(cve_rows))


ConnectionFactory = Callable[[], AbstractContextManager[Connection]]


class PostgresSecurityKnowledgeRepository:
    """Execute guarded SQL under transaction-level read-only controls."""

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        row_limit: int,
        statement_timeout_ms: int,
    ) -> None:
        if row_limit < 1:
            raise ValueError("row_limit must be at least 1")
        if statement_timeout_ms < 1:
            raise ValueError("statement_timeout_ms must be at least 1")
        self._connection_factory = connection_factory
        self._row_limit = row_limit
        self._statement_timeout_ms = statement_timeout_ms

    def execute_readonly(self, sql: str) -> QueryResult:
        try:
            with self._connection_factory() as connection:
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(
                    text("SELECT set_config('statement_timeout', :timeout, true)"),
                    {"timeout": f"{self._statement_timeout_ms}ms"},
                )
                result = connection.execute(text(sql))
                columns = tuple(str(column) for column in result.keys())
                rows = tuple(
                    tuple(_normalize_scalar(value) for value in row)
                    for row in result.fetchmany(self._row_limit)
                )
                return QueryResult(columns=columns, rows=rows)
        except SQLAlchemyError as error:
            raise IntelligenceUnavailableError("postgresql", "readonly_query_failed") from error


def _normalize_scalar(value: object) -> QueryScalar:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)
