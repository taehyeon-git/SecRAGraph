from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from security_review.domain.models import (
    Confidence,
    Finding,
    ReportSummary,
    RiskSummary,
    ScanReport,
    ScanStatus,
    Severity,
)


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "id": "GITLEAKS:abc",
        "rule_id": "GITLEAKS/generic-api-key",
        "category": "secret",
        "severity": Severity.HIGH,
        "file_path": "src/settings.py",
        "line_start": 2,
        "message": "Potential secret",
        "redacted_evidence": "token=***REDACTED***",
        "confidence": Confidence.HIGH,
        "remediation": "Move the value to a secret store.",
    }
    values.update(overrides)
    return Finding.model_validate(values)


@pytest.mark.parametrize(
    "file_path",
    ["C:/private/app.py", "/etc/passwd", "../outside.py", "src/../../outside.py", ""],
)
def test_finding_rejects_non_relative_path(file_path: str) -> None:
    with pytest.raises(ValidationError, match="relative"):
        make_finding(file_path=file_path)


def test_finding_normalizes_windows_separators() -> None:
    finding = make_finding(file_path=r"src\settings.py")
    assert finding.file_path == "src/settings.py"


def test_finding_rejects_line_end_before_line_start() -> None:
    with pytest.raises(ValidationError, match="line_end"):
        make_finding(line_start=5, line_end=4)


def test_finding_is_immutable() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError, match="frozen"):
        finding.message = "changed"


def test_report_summary_counts_severity_and_category() -> None:
    findings = (
        make_finding(id="GITLEAKS:a", severity=Severity.HIGH),
        make_finding(id="GITLEAKS:b", severity=Severity.HIGH),
        make_finding(id="OG:c", category="sast", severity=Severity.MEDIUM),
    )
    summary = ReportSummary.from_findings(findings)
    assert summary.total == 3
    assert summary.by_severity[Severity.HIGH] == 2
    assert summary.by_severity[Severity.MEDIUM] == 1
    assert summary.by_category == {"sast": 1, "secret": 2}


def test_report_summary_count_mappings_are_immutable() -> None:
    summary = ReportSummary.from_findings([make_finding()])

    with pytest.raises(TypeError):
        summary.by_category["secret"] = 99  # type: ignore[index]


def test_scan_report_serializes_uuid_and_utc_timestamp() -> None:
    finding = make_finding()
    report = ScanReport(
        scan_id=UUID("00000000-0000-4000-8000-000000000001"),
        created_at=datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        target_name="sample",
        summary=ReportSummary.from_findings((finding,)),
        risk=RiskSummary(
            score=7,
            level=Severity.HIGH,
            counts={severity: int(severity is Severity.HIGH) for severity in Severity},
        ),
        findings=(finding,),
        tool_version="0.1.0",
        rule_set_version="2026.09.1",
    )
    payload = report.model_dump(mode="json")
    assert payload["scan_id"] == "00000000-0000-4000-8000-000000000001"
    assert payload["created_at"] == "2026-10-08T12:00:00Z"


def test_scan_execution_normalizes_relative_coverage_paths() -> None:
    from security_review.domain.models import ScanExecution

    execution = ScanExecution(
        engine="codeql",
        kind="sast",
        status="completed",
        version="2.23.0",
        elapsed_ms=321,
        eligible_files=(r"src\app.py",),
        scanned_files=(r"src\app.py",),
        languages=("python",),
        checks=("security-extended",),
    )

    assert execution.model_dump(mode="json")["scanned_files"] == ["src/app.py"]
    with pytest.raises(ValidationError, match="frozen"):
        execution.status = "error"


@pytest.mark.parametrize("unsafe_path", ["../private.py", "/private.py", "C:/private.py"])
def test_scan_execution_rejects_unsafe_coverage_paths(unsafe_path: str) -> None:
    from security_review.domain.models import ScanExecution

    with pytest.raises(ValidationError, match="relative"):
        ScanExecution(
            engine="codeql",
            kind="sast",
            status="completed",
            elapsed_ms=1,
            eligible_files=(unsafe_path,),
            scanned_files=(),
        )


def test_trace_location_rejects_source_text_and_unsafe_paths() -> None:
    from security_review.domain.models import TraceLocation

    with pytest.raises(ValidationError, match="extra_forbidden"):
        TraceLocation(file_path="src/app.py", line_start=1, role="source", text="raw secret")
    with pytest.raises(ValidationError, match="relative"):
        TraceLocation(file_path="../../private.py", line_start=1, role="sink")
