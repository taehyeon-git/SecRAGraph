import json

import pytest

from security_review.domain.models import Confidence, Finding, ScanStatus, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.sarif import render_sarif


def make_finding(
    *,
    identifier: str = "opengrep:stable",
    path: str = "src/app.py",
    line: int = 4,
    message: str = "Untrusted input reaches a dangerous operation.",
    rule_id: str = "OPENGREP001",
    cwe_ids: tuple[str, ...] = ("CWE-95",),
    engine: str = "opengrep",
) -> Finding:
    return Finding(
        id=identifier,
        rule_id=rule_id,
        category="code_pattern",
        severity=Severity.HIGH,
        file_path=path,
        line_start=line,
        message=message,
        redacted_evidence="API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=cwe_ids,
        remediation="Use an explicit parser.",
        engine=engine,
    )


def test_report_deduplicates_and_orders_findings() -> None:
    later = make_finding(identifier="opengrep:later", path="z.py", line=8)
    earlier = make_finding(identifier="opengrep:earlier", path="a.py", line=2)

    report = build_report("sample", [later, earlier, earlier])

    assert [item.id for item in report.findings] == ["opengrep:earlier", "opengrep:later"]
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


def test_incomplete_engine_sets_warning_status_without_text_warning() -> None:
    from security_review.domain.models import ScanExecution

    execution = ScanExecution(
        engine="codeql",
        kind="sast",
        status="partial",
        elapsed_ms=250,
        reason="analysis_timeout",
    )

    report = build_report("sample", [], executions=(execution,))

    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS
    assert report.warnings == ()


def test_report_version_and_multiengine_cwe_mappings_reach_outputs() -> None:
    findings = (
        make_finding(
            identifier="opengrep:unsafe-deserialization",
            rule_id="OPENGREP001",
            cwe_ids=("CWE-502",),
        ),
        make_finding(
            identifier="checkov:tls-verification",
            rule_id="CHECKOV001",
            cwe_ids=("CWE-295",),
            engine="checkov",
            path="config.yaml",
        ),
    )
    report = build_report("sample", findings)

    assert report.rule_set_version
    run = json.loads(render_sarif(report))["runs"][0]
    assert {result["ruleId"]: result["properties"]["cweIds"] for result in run["results"]} == {
        "CHECKOV001": ["CWE-295"],
        "OPENGREP001": ["CWE-502"],
    }
    assert {rule["id"]: rule["properties"]["tags"] for rule in run["tool"]["driver"]["rules"]} == {
        "CHECKOV001": ["security", "CWE-295"],
        "OPENGREP001": ["security", "CWE-502"],
    }


def test_target_name_never_retains_a_host_absolute_path() -> None:
    report = build_report(r"C:\Users\person\private\sample", [])

    assert report.target_name == "sample"
    assert "person" not in report.model_dump_json()


@pytest.mark.parametrize("warning", [r"C:\private\app.py:unreadable", "/etc/app.py:unreadable"])
def test_absolute_paths_are_rejected_from_warnings(warning: str) -> None:
    with pytest.raises(ValueError, match="relative"):
        build_report("sample", [], [warning])
