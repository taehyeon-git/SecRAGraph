import json
from pathlib import Path

import pytest

from security_review.application import scan_path
from security_review.domain.models import Confidence, Finding, ScanReport, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.sarif import render_sarif
from security_review.reporting.types import ReportFormat, render_report
from security_review.scanner.engine import scan_text
from security_review.scanner.files import ScanLimits


@pytest.fixture
def report() -> ScanReport:
    fixture = Path(__file__).parents[2] / "fixtures" / "report.json"
    return ScanReport.model_validate_json(fixture.read_text(encoding="utf-8"))


def finding(identifier: str, severity: Severity, rule_id: str = "TEST001") -> Finding:
    return Finding(
        id=identifier,
        rule_id=rule_id,
        category="code_pattern",
        severity=severity,
        file_path="src/app.py",
        line_start=2,
        message="Test finding.",
        redacted_evidence="safe evidence",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-20",),
        remediation="Validate the input.",
    )


def test_sarif_contains_consistent_results(report: ScanReport) -> None:
    payload = json.loads(render_sarif(report))

    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecRAGraph"
    assert run["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/config%20file%231%25.py"
    assert location["region"] == {"startLine": 7, "endLine": 7}
    assert "uriBaseId" not in location["artifactLocation"]


def test_unsafe_yaml_finding_has_same_identity_in_json_and_sarif(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text("import yaml\nvalue = yaml.unsafe_load(data)\n", encoding="utf-8")

    report = scan_path(target, ScanLimits())
    assert len(report.findings) == 1
    json_finding = json.loads(render_json(report))["findings"][0]
    run = json.loads(render_sarif(report))["runs"][0]
    sarif_result = run["results"][0]

    assert json_finding["rule_id"] == sarif_result["ruleId"] == "PY004"
    assert json_finding["id"] == sarif_result["properties"]["findingId"]
    assert json_finding["cwe_ids"] == sarif_result["properties"]["cweIds"] == ["CWE-502"]
    assert run["tool"]["driver"]["rules"][0]["properties"]["tags"] == ["security", "CWE-502"]
    assert json_finding["severity"] == "high"
    assert json_finding["confidence"] == "medium"
    assert json_finding["category"] == "code_pattern"
    assert json_finding["line_start"] == 2


def test_sarif_path_prefix_does_not_change_finding_identity(report: ScanReport) -> None:
    payload = json.loads(render_sarif(report, path_prefix="checkout"))
    result = payload["runs"][0]["results"][0]

    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "checkout/src/config%20file%231%25.py"
    )
    baseline = json.loads(render_sarif(report))["runs"][0]["results"][0]
    assert result["partialFingerprints"] == baseline["partialFingerprints"]
    assert report.findings[0].file_path == "src/config file#1%.py"


def test_sarif_fingerprint_survives_unrelated_line_insertion() -> None:
    source = 'API_KEY = "sk-test-example-value"\n'
    before = build_report("sample", scan_text("settings.py", source))
    after = build_report("sample", scan_text("settings.py", "answer = 42\n" + source))
    before_result = json.loads(render_sarif(before))["runs"][0]["results"][0]
    after_result = json.loads(render_sarif(after))["runs"][0]["results"][0]

    assert before.findings[0].id != after.findings[0].id
    assert before_result["partialFingerprints"] == after_result["partialFingerprints"]
    assert "sk-test-example-value" not in json.dumps(before_result)


def test_sarif_fingerprints_distinguish_identical_matches_in_one_file() -> None:
    source = 'API_KEY = "sk-test-example-value"\n' * 2
    report = build_report("sample", scan_text("settings.py", source))
    results = json.loads(render_sarif(report))["runs"][0]["results"]

    assert len(results) == 2
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in results}) == 2


def test_sarif_fingerprint_does_not_hash_raw_secret_value() -> None:
    first = build_report("sample", scan_text("settings.py", 'API_KEY = "sk-test-example-value"'))
    second = build_report("sample", scan_text("settings.py", 'API_KEY = "sk-test-another-value"'))

    first_result = json.loads(render_sarif(first))["runs"][0]["results"][0]
    second_result = json.loads(render_sarif(second))["runs"][0]["results"][0]
    assert first_result["partialFingerprints"] == second_result["partialFingerprints"]


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_sarif_maps_severity_levels(severity: Severity, expected: str) -> None:
    report = build_report("sample", [finding(f"TEST001:{severity.value}", severity)])

    result = json.loads(render_sarif(report))["runs"][0]["results"][0]

    assert result["level"] == expected


def test_sarif_has_one_sorted_descriptor_per_rule() -> None:
    report = build_report(
        "sample",
        [
            finding("Z002:1", Severity.LOW, "Z002"),
            finding("A001:1", Severity.HIGH, "A001"),
            finding("A001:2", Severity.MEDIUM, "A001").model_copy(update={"line_start": 3}),
        ],
    )

    run = json.loads(render_sarif(report))["runs"][0]

    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["A001", "Z002"]
    assert [result["ruleIndex"] for result in run["results"]] == [0, 1, 0]
    assert run["tool"]["driver"]["rules"][0]["help"]["text"] == "Validate the input."


def test_sarif_dispatch_and_serialization_are_stable(report: ScanReport) -> None:
    first = render_sarif(report)

    assert render_report(report, ReportFormat.SARIF) == first
    assert render_sarif(report) == first
    assert (
        "\\"
        not in json.loads(first)["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
    )


def test_raw_secret_never_reaches_sarif() -> None:
    token = "sk-test-never-render-this"
    report = build_report("sample", scan_text("settings.py", f'API_KEY="{token}"'))

    rendered = render_sarif(report)

    assert token not in rendered
    assert "***REDACTED***" in rendered
