"""Small, source-free result contract shared by external scanner adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from security_review.domain.models import Finding

ExternalStatus = Literal["completed", "partial", "skipped", "not_run", "error"]


@dataclass(frozen=True, slots=True)
class ExternalExecution:
    """Execution evidence; file lists distinguish candidates from proven output paths."""

    scanner: str
    version: str | None
    status: ExternalStatus
    eligible_files: tuple[str, ...] = ()
    inspected_files: tuple[str, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    checks: tuple[str, ...] = ()
    duration_ms: int = 0
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExternalScanResult:
    """Normalized findings plus one scanner's execution record."""

    findings: tuple[Finding, ...]
    execution: ExternalExecution
