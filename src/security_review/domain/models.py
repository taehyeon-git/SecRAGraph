"""Validated, infrastructure-independent security review models."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
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
_FULL_GIT_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _git_commit(value: str | None) -> str | None:
    if value is not None and not _FULL_GIT_COMMIT.fullmatch(value):
        raise ValueError("git_commit must be a full lowercase SHA-1 or SHA-256 object ID")
    return value


def _image_id(value: str | None) -> str | None:
    if value is not None and not _IMAGE_ID.fullmatch(value):
        raise ValueError("image ID must be a lowercase sha256 digest")
    return value


def _sha256(value: str | None) -> str | None:
    if value is not None and not _SHA256.fullmatch(value):
        raise ValueError("SHA-256 must contain 64 lowercase hexadecimal characters")
    return value


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
    kind: Literal["sast", "dependency", "secret", "configuration", "dast", "container"]
    status: Literal["completed", "partial", "not_run", "error", "skipped"]
    version: str | None = Field(default=None, max_length=128)
    elapsed_ms: int = Field(ge=0)
    eligible_files: tuple[str, ...] = ()
    scanned_files: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    eligible_endpoints: tuple[str, ...] = ()
    observed_alert_endpoints: tuple[str, ...] = ()
    revision_base: str | None = None
    revision_head: str | None = None
    selected_commit_count: int | None = Field(default=None, ge=1)
    image_id: str | None = None
    image_local_id: str | None = None
    image_tar_sha256: str | None = None
    image_db_updated_at: datetime | None = None
    image_vulnerability_count: int | None = Field(default=None, ge=0)
    image_config_count: int | None = Field(default=None, ge=0)
    sbom_sha256: str | None = None
    sbom_component_count: int | None = Field(default=None, ge=1)
    reason: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,127}$")

    @field_validator("revision_base", "revision_head")
    @classmethod
    def require_full_commit(cls, value: str | None) -> str | None:
        return _git_commit(value)

    @field_validator("image_id", "image_local_id")
    @classmethod
    def require_image_id(cls, value: str | None) -> str | None:
        return _image_id(value)

    @field_validator("image_tar_sha256", "sbom_sha256")
    @classmethod
    def require_sha256(cls, value: str | None) -> str | None:
        return _sha256(value)

    @field_validator("image_db_updated_at")
    @classmethod
    def require_utc_db_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("image DB time must use UTC")
        return value

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
        if self.kind in {"dast", "container"} and (self.eligible_files or self.scanned_files):
            raise ValueError("DAST and container coverage cannot claim source files")
        if self.kind != "dast" and (self.eligible_endpoints or self.observed_alert_endpoints):
            raise ValueError("HTTP endpoint coverage requires DAST kind")
        if self.revision_base is not None and self.revision_head is None:
            raise ValueError("revision_base requires revision_head")
        if self.revision_base is not None and self.revision_head is not None:
            if len(self.revision_base) != len(self.revision_head):
                raise ValueError("Git revision bounds must use the same object ID width")
        if (self.revision_head is None) != (self.selected_commit_count is None):
            raise ValueError("revision_head and selected_commit_count are required together")
        if self.kind != "secret" and self.revision_head is not None:
            raise ValueError("Git history coverage requires secret kind")
        if self.revision_head is not None and (self.eligible_files or self.scanned_files):
            raise ValueError("Git history coverage cannot claim an inspected-file inventory")
        image_values = (
            self.image_id,
            self.image_local_id,
            self.image_tar_sha256,
            self.image_db_updated_at,
            self.image_vulnerability_count,
            self.image_config_count,
            self.sbom_sha256,
            self.sbom_component_count,
        )
        if self.kind == "container":
            if self.revision_head is not None:
                raise ValueError("container coverage cannot claim Git history")
            if self.status == "completed" and any(value is None for value in image_values):
                raise ValueError("completed container scan requires image and SBOM provenance")
        elif any(value is not None for value in image_values):
            raise ValueError("image provenance requires container kind")
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
    git_commit: str | None = None
    image_id: str | None = None
    image_resource: str | None = None
    upstream_severity: Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    severity_source: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
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

    @field_validator("git_commit")
    @classmethod
    def require_full_commit(cls, value: str | None) -> str | None:
        return _git_commit(value)

    @field_validator("image_id")
    @classmethod
    def require_image_id(cls, value: str | None) -> str | None:
        return _image_id(value)

    @field_validator("image_resource")
    @classmethod
    def require_image_resource(cls, value: str | None) -> str | None:
        if value is not None and (
            not value or len(value) > 1_024 or any(not 33 <= ord(char) <= 126 for char in value)
        ):
            raise ValueError("image resource must be bounded printable text without spaces")
        return value

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        has_source = self.file_path is not None
        has_http = self.http_method is not None and self.http_path is not None
        has_image = self.image_id is not None and self.image_resource is not None
        if sum((has_source, has_http, has_image)) != 1:
            raise ValueError("finding requires exactly one source, HTTP or image location")
        if has_source:
            if (
                self.line_start is None
                or self.http_method is not None
                or self.http_path is not None
                or self.image_id is not None
                or self.image_resource is not None
            ):
                raise ValueError("source location requires a line and no HTTP location")
            if self.line_end is not None and self.line_end < self.line_start:
                raise ValueError("line_end must be greater than or equal to line_start")
        elif self.line_start is not None or self.line_end is not None or self.trace:
            raise ValueError("HTTP or image location cannot claim a source line or trace")
        if has_image:
            if (
                self.http_method is not None
                or self.http_path is not None
                or self.git_commit is not None
            ):
                raise ValueError("image location cannot claim HTTP or Git provenance")
            if self.upstream_severity is None:
                raise ValueError("image finding requires upstream severity")
        elif (
            self.image_id is not None
            or self.image_resource is not None
            or self.upstream_severity is not None
            or self.severity_source is not None
        ):
            raise ValueError("image metadata requires an image location")
        if self.git_commit is not None:
            if not has_source:
                raise ValueError("git_commit requires a source path and line")
            if self.trace:
                raise ValueError("historical finding cannot claim an unversioned trace")
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
