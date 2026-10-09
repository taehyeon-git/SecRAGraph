import json

import pytest

from security_review.domain.models import Confidence, Finding, ScanStatus, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.sarif import render_sarif
from security_review.scanner.engine import scan_text


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


def test_report_version_and_new_rules_cwe_mappings_reach_outputs() -> None:
    findings = (
        *scan_text("sample.py", "import yaml\nvalue = yaml.unsafe_load(data)\n"),
        *scan_text(".env", "NODE_TLS_REJECT_UNAUTHORIZED=0\n"),
    )
    report = build_report("sample", findings)

    assert report.rule_set_version == "2026.10.2"
    run = json.loads(render_sarif(report))["runs"][0]
    assert {result["ruleId"]: result["properties"]["cweIds"] for result in run["results"]} == {
        "JS001": ["CWE-295"],
        "PY004": ["CWE-502"],
    }
    assert {rule["id"]: rule["properties"]["tags"] for rule in run["tool"]["driver"]["rules"]} == {
        "JS001": ["security", "CWE-295"],
        "PY004": ["security", "CWE-502"],
    }


def test_target_name_never_retains_a_host_absolute_path() -> None:
    report = build_report(r"C:\Users\person\private\sample", [])

    assert report.target_name == "sample"
    assert "person" not in report.model_dump_json()


@pytest.mark.parametrize("warning", [r"C:\private\app.py:unreadable", "/etc/app.py:unreadable"])
def test_absolute_paths_are_rejected_from_warnings(warning: str) -> None:
    with pytest.raises(ValueError, match="relative"):
        build_report("sample", [], [warning])
