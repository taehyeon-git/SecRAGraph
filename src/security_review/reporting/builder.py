"""Canonical security-review report assembly."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from security_review import __version__
from security_review.domain.models import (
    Finding,
    ReportSummary,
    ScanExecution,
    ScanReport,
    ScanStatus,
)
from security_review.domain.risk import calculate_risk

RULE_SET_VERSION = "2026.10.27-multiengine.1"


def finding_sort_key(finding: Finding) -> tuple[int, str, int, str, str]:
    """Order source and HTTP findings without comparing nullable locations."""

    if finding.file_path is not None:
        return (0, finding.file_path, finding.line_start or 0, finding.rule_id, finding.id)
    return (
        1,
        f"{finding.http_method} {finding.http_path}",
        0,
        finding.rule_id,
        finding.id,
    )


def normalize_target_name(target_name: str) -> str:
    """Reduce a display target to a report-safe leaf name."""

    normalized = target_name.replace("\\", "/").rstrip("/")
    leaf = normalized.rsplit("/", maxsplit=1)[-1].strip()
    return leaf or "scan-target"


def _safe_warning(warning: str) -> str:
    normalized = warning.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        raise ValueError("warning paths must be relative")
    return normalized


def normalize_findings(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    """Deduplicate and order findings without weakening ID collision checks."""

    unique: dict[str, Finding] = {}
    for finding in findings:
        existing = unique.get(finding.id)
        if existing is not None and existing != finding:
            raise ValueError(f"finding ID collision for {finding.id}")
        unique[finding.id] = finding
    return tuple(sorted(unique.values(), key=finding_sort_key))


def normalize_warnings(warnings: Sequence[str]) -> tuple[str, ...]:
    """Normalize and deduplicate report warnings while preserving first-seen order."""

    return tuple(dict.fromkeys(_safe_warning(warning) for warning in warnings))


def build_report(
    target_name: str,
    findings: Sequence[Finding],
    warnings: Sequence[str] = (),
    *,
    executions: Sequence[ScanExecution] = (),
) -> ScanReport:
    """Build the single report model consumed by every output adapter."""

    ordered = normalize_findings(findings)
    ordered_warnings = normalize_warnings(warnings)
    ordered_executions = tuple(executions)
    incomplete_execution = any(
        execution.status not in {"completed", "skipped"} for execution in ordered_executions
    )
    return ScanReport(
        scan_id=uuid4(),
        created_at=datetime.now(UTC),
        status=(
            ScanStatus.COMPLETED_WITH_WARNINGS
            if ordered_warnings or incomplete_execution
            else ScanStatus.COMPLETED
        ),
        target_name=normalize_target_name(target_name),
        summary=ReportSummary.from_findings(ordered),
        risk=calculate_risk(ordered),
        findings=ordered,
        warnings=ordered_warnings,
        tool_version=__version__,
        rule_set_version=RULE_SET_VERSION,
        executions=ordered_executions,
    )
