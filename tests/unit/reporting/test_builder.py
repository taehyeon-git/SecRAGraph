import pytest

from security_review.domain.models import Confidence, Finding, ScanStatus, Severity
from security_review.reporting.builder import build_report


def make_finding(
    *,
    identifier: str = "PY001:stable",
    path: str = "src/app.py",
    line: int = 4,
    message: str = "Dynamic evaluation detected.",
) -> Finding:
    return Finding(
        id=identifier,
        rule_id="PY001",
        category="code_pattern",
        severity=Severity.HIGH,
        file_path=path,
        line_start=line,
        message=message,
        redacted_evidence="API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-95",),
        remediation="Use an explicit parser.",
    )


def test_report_deduplicates_and_orders_findings() -> None:
    later = make_finding(identifier="PY001:later", path="z.py", line=8)
    earlier = make_finding(identifier="PY001:earlier", path="a.py", line=2)

    report = build_report("sample", [later, earlier, earlier])

    assert [item.id for item in report.findings] == ["PY001:earlier", "PY001:later"]
    assert report.summary.total == 2


def test_conflicting_duplicate_id_is_rejected() -> None:
    first = make_finding()
    conflicting = make_finding(message="Different finding with the same ID.")

    with pytest.raises(ValueError, match="collision"):
        build_report("sample", [first, conflicting])


def test_warnings_set_completed_with_warnings_status() -> None:
    report = build_report("sample", [], ["file.py:binary_or_invalid_utf8"])

    assert report.status == ScanStatus.COMPLETED_WITH_WARNINGS
    assert report.warnings == ("file.py:binary_or_invalid_utf8",)
    assert report.risk.score == 0
    assert report.risk.level == Severity.LOW


def test_target_name_never_retains_a_host_absolute_path() -> None:
    report = build_report(r"C:\Users\person\private\sample", [])

    assert report.target_name == "sample"
    assert "person" not in report.model_dump_json()


@pytest.mark.parametrize("warning", [r"C:\private\app.py:unreadable", "/etc/app.py:unreadable"])
def test_absolute_paths_are_rejected_from_warnings(warning: str) -> None:
    with pytest.raises(ValueError, match="relative"):
        build_report("sample", [], [warning])
