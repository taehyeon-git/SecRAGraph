"""Validated, infrastructure-independent security review models."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


class Severity(StrEnum):
    """Normalized finding and report severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """Confidence in a deterministic or enriched finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanStatus(StrEnum):
    """Terminal scan statuses for the first synchronous release."""

    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"


class SourceReference(BaseModel):
    """Evidence reference attached to a security finding."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    source_url: str | None = None
    page: int | None = Field(default=None, ge=1)
    section: str | None = None
    score: float | None = Field(default=None, ge=0, le=1)


def _relative_report_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not value or not path.parts or path.as_posix() == ".":
        raise ValueError("file_path must be relative")
    if path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
        raise ValueError("file_path must be relative")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("file_path must not contain control characters")
    return path.as_posix()


_HTTP_METHOD = re.compile(r"[A-Z]{1,16}\Z")


def _http_path(value: str) -> str:
    """Accept an origin-free URL path without query, fragment or raw controls."""

    if (
        len(value) > 2_048
        or not value.startswith("/")
        or value.startswith("//")
        or any(character in "\\?#" or not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError("http_path must be a bounded origin-free URL path")
    return value


def _http_endpoint(value: str) -> str:
    method, separator, path = value.partition(" ")
    if not separator or not _HTTP_METHOD.fullmatch(method):
        raise ValueError("endpoint must contain an HTTP method and path")
    return f"{method} {_http_path(path)}"


class TraceLocation(BaseModel):
    """Source-free location in an optional cross-file source-to-sink flow."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_path: str
    line_start: int = Field(ge=1)
    line_end: int | None = Field(default=None, ge=1)
    role: Literal["source", "step", "sink"]

    @field_validator("file_path")
    @classmethod
    def require_relative_path(cls, value: str) -> str:
        return _relative_report_path(value)

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        if self.line_end is not None and self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class ScanExecution(BaseModel):
    """Bounded, source-free coverage for one scanner engine invocation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    kind: Literal["sast", "dependency", "secret", "configuration", "dast"]
    status: Literal["completed", "partial", "not_run", "error", "skipped"]
    version: str | None = Field(default=None, max_length=128)
    elapsed_ms: int = Field(ge=0)
    eligible_files: tuple[str, ...] = ()
    scanned_files: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    eligible_endpoints: tuple[str, ...] = ()
    observed_alert_endpoints: tuple[str, ...] = ()
    reason: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,127}$")

    @field_validator("eligible_files", "scanned_files")
    @classmethod
    def require_relative_files(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 10_000:
            raise ValueError("too many coverage files")
        normalized = tuple(_relative_report_path(path) for path in value)
        if len(normalized) != len(set(normalized)):
            raise ValueError("coverage files must be unique")
        return normalized

    @field_validator("languages", "checks")
    @classmethod
    def require_bounded_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 1_000 or any(
            not item
            or len(item) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        ):
            raise ValueError("coverage labels must be bounded printable text")
        return value

    @field_validator("eligible_endpoints", "observed_alert_endpoints")
    @classmethod
    def require_http_endpoints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 2_000:
            raise ValueError("too many HTTP endpoints")
        normalized = tuple(_http_endpoint(endpoint) for endpoint in value)
        if len(normalized) != len(set(normalized)):
            raise ValueError("HTTP endpoints must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_coverage_kind(self) -> Self:
        if self.kind == "dast" and (self.eligible_files or self.scanned_files):
            raise ValueError("DAST coverage cannot claim source files")
        if self.kind != "dast" and (self.eligible_endpoints or self.observed_alert_endpoints):
            raise ValueError("HTTP endpoint coverage requires DAST kind")
        return self


class Finding(BaseModel):
    """One normalized security issue with already-redacted evidence."""

    model_config = ConfigDict(frozen=True)

    id: str
    rule_id: str
    category: str
    severity: Severity
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    http_method: str | None = Field(default=None, pattern=r"^[A-Z]{1,16}$")
    http_path: str | None = None
    message: str
    redacted_evidence: str
    confidence: Confidence
    cwe_ids: tuple[str, ...] = ()
    remediation: str
    references: tuple[SourceReference, ...] = ()
    engine: str = Field(default="secragraph", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    trace: tuple[TraceLocation, ...] = ()

    @field_validator("file_path")
    @classmethod
    def require_relative_path(cls, value: str | None) -> str | None:
        return _relative_report_path(value) if value is not None else None

    @field_validator("http_path")
    @classmethod
    def require_origin_free_http_path(cls, value: str | None) -> str | None:
        return _http_path(value) if value is not None else None

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        has_source = self.file_path is not None
        has_http = self.http_method is not None and self.http_path is not None
        if has_source == has_http:
            raise ValueError("finding requires exactly one source or HTTP location")
        if has_source:
            if (
                self.line_start is None
                or self.http_method is not None
                or self.http_path is not None
            ):
                raise ValueError("source location requires a line and no HTTP location")
            if self.line_end is not None and self.line_end < self.line_start:
                raise ValueError("line_end must be greater than or equal to line_start")
        elif self.line_start is not None or self.line_end is not None or self.trace:
            raise ValueError("HTTP location cannot claim a source line or trace")
        if len(self.trace) > 64:
            raise ValueError("trace must contain at most 64 locations")
        return self


class RiskSummary(BaseModel):
    """Deterministic aggregate risk for one report."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0)
    level: Severity
    counts: Mapping[Severity, int]

    @field_validator("counts", mode="after")
    @classmethod
    def freeze_counts(cls, value: Mapping[Severity, int]) -> Mapping[Severity, int]:
        return MappingProxyType(dict(value))

    @field_serializer("counts")
    def serialize_counts(self, value: Mapping[Severity, int]) -> dict[Severity, int]:
        return dict(value)


class ReportSummary(BaseModel):
    """Finding totals used by every report representation."""

    model_config = ConfigDict(frozen=True)

    total: int = Field(ge=0)
    by_severity: Mapping[Severity, int]
    by_category: Mapping[str, int]

    @field_validator("by_severity", mode="after")
    @classmethod
    def freeze_severity_counts(cls, value: Mapping[Severity, int]) -> Mapping[Severity, int]:
        return MappingProxyType(dict(value))

    @field_validator("by_category", mode="after")
    @classmethod
    def freeze_category_counts(cls, value: Mapping[str, int]) -> Mapping[str, int]:
        return MappingProxyType(dict(value))

    @field_serializer("by_severity")
    def serialize_severity_counts(self, value: Mapping[Severity, int]) -> dict[Severity, int]:
        return dict(value)

    @field_serializer("by_category")
    def serialize_category_counts(self, value: Mapping[str, int]) -> dict[str, int]:
        return dict(value)

    @classmethod
    def from_findings(cls, findings: Sequence[Finding]) -> ReportSummary:
        severity_counts = Counter(item.severity for item in findings)
        category_counts = Counter(item.category for item in findings)
        return cls(
            total=len(findings),
            by_severity={severity: severity_counts[severity] for severity in Severity},
            by_category=dict(sorted(category_counts.items())),
        )


class ScanReport(BaseModel):
    """Canonical scan report rendered by all delivery interfaces."""

    model_config = ConfigDict(frozen=True)

    scan_id: UUID
    created_at: datetime
    status: ScanStatus
    target_name: str
    summary: ReportSummary
    risk: RiskSummary
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()
    tool_version: str
    rule_set_version: str
    executions: tuple[ScanExecution, ...] = ()
