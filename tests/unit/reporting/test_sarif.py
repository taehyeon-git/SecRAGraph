import json
from pathlib import Path

import pytest

from security_review.domain.models import Confidence, Finding, ScanReport, Severity, SourceReference
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.sarif import render_sarif
from security_review.reporting.types import ReportFormat, render_report
from security_review.scanner.external_detectors import _parse_gitleaks


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


def secret_finding(identifier: str = "gitleaks:stable", line: int = 2) -> Finding:
    return Finding(
        id=identifier,
        rule_id="gitleaks:generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        file_path="settings.py",
        line_start=line,
        message="A secret-like value was found.",
        redacted_evidence="API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-798",),
        remediation="Replace the credential and load it from a secret store.",
        engine="gitleaks",
    )


def parsed_secret_finding(root: Path, secret: str) -> Finding:
    return _parse_gitleaks(
        [
            {
                "RuleID": "generic-api-key",
                "File": "settings.py",
                "StartLine": 2,
                "EndLine": 2,
                "StartColumn": 1,
                "Secret": secret,
                "Match": f"API_KEY={secret}",
            }
        ],
        root,
        frozenset({"settings.py"}),
    )[0]


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


def test_external_sast_finding_has_same_identity_in_json_and_sarif() -> None:
    external_finding = finding(
        "opengrep:unsafe-load", Severity.HIGH, "opengrep:unsafe-yaml-load"
    ).model_copy(
        update={
            "engine": "opengrep",
            "cwe_ids": ("CWE-502",),
            "confidence": Confidence.MEDIUM,
        }
    )
    report = build_report("config.py", [external_finding])
    assert len(report.findings) == 1
    json_finding = json.loads(render_json(report))["findings"][0]
    run = json.loads(render_sarif(report))["runs"][0]
    sarif_result = run["results"][0]

    assert json_finding["rule_id"] == sarif_result["ruleId"] == "opengrep:unsafe-yaml-load"
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


def test_sarif_fingerprint_survives_another_finding_on_earlier_line() -> None:
    secret = secret_finding()
    before = build_report("sample", [secret])
    after = build_report(
        "sample",
        [secret, finding("opengrep:earlier", Severity.HIGH).model_copy(update={"line_start": 1})],
    )
    before_result = next(
        item
        for item in json.loads(render_sarif(before))["runs"][0]["results"]
        if item["ruleId"] == "gitleaks:generic-api-key"
    )
    after_result = next(
        item
        for item in json.loads(render_sarif(after))["runs"][0]["results"]
        if item["ruleId"] == "gitleaks:generic-api-key"
    )

    assert before.findings[0].id == next(
        item.id for item in after.findings if item.rule_id == "gitleaks:generic-api-key"
    )
    assert before_result["partialFingerprints"] == after_result["partialFingerprints"]
    assert "sk-test-example-value" not in json.dumps(before_result)


def test_sarif_fingerprint_changes_when_source_line_moves() -> None:
    before = build_report("sample", [secret_finding(line=1)])
    after = build_report("sample", [secret_finding(line=2)])
    before_result = json.loads(render_sarif(before))["runs"][0]["results"][0]
    after_result = json.loads(render_sarif(after))["runs"][0]["results"][0]

    assert before_result["partialFingerprints"] != after_result["partialFingerprints"]


def test_sarif_fingerprints_distinguish_identical_matches_in_one_file() -> None:
    report = build_report(
        "sample", [secret_finding("gitleaks:first", 1), secret_finding("gitleaks:second", 2)]
    )
    results = json.loads(render_sarif(report))["runs"][0]["results"]

    assert len(results) == 2
    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in results}) == 2


def test_sarif_keeps_distinct_osv_advisories_in_one_lockfile() -> None:
    advisories = [
        Finding(
            id=f"OSV001:{suffix}",
            rule_id="OSV001",
            category="dependency",
            severity=Severity.INFO,
            file_path="package-lock.json",
            line_start=1,
            message=f"OSV advisory GHSA-{suffix} matches a locked dependency.",
            redacted_evidence="Exact locked dependency coordinate matched an OSV advisory.",
            confidence=Confidence.HIGH,
            remediation="Review the advisory and upgrade.",
        )
        for suffix in ("one", "two")
    ]
    report = build_report("package-lock.json", advisories)

    run = json.loads(render_sarif(report))["runs"][0]
    assert len(run["results"]) == 2
    assert (
        len({item["partialFingerprints"]["primaryLocationLineHash"] for item in run["results"]})
        == 2
    )
    assert run["tool"]["driver"]["rules"][0]["shortDescription"]["text"] == (
        "Vulnerable locked dependency reported by OSV.dev."
    )
    assert {item["message"]["text"] for item in run["results"]} == {
        advisory.message for advisory in advisories
    }


def test_sarif_osv_result_links_only_a_validated_public_advisory() -> None:
    advisory = Finding(
        id="OSV001:stable",
        rule_id="OSV001",
        category="dependency",
        severity=Severity.INFO,
        file_path="uv.lock",
        line_start=1,
        message="OSV advisory GHSA-abcd-1234-5678 matches jinja2 2.4.1.",
        redacted_evidence="Exact locked dependency coordinate matched an OSV advisory.",
        confidence=Confidence.HIGH,
        remediation="Review the advisory and upgrade.",
        references=(
            SourceReference(
                id="forged",
                title="forged",
                source_url="https://example.test/secret",
            ),
            SourceReference(
                id="osv:GHSA-abcd-1234-5678",
                title="GHSA-abcd-1234-5678",
                source_url="https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
            ),
        ),
    )
    result = json.loads(render_sarif(build_report("uv.lock", (advisory,))))["runs"][0]["results"][0]

    assert result["properties"]["osvAdvisoryUrl"] == (
        "https://osv.dev/vulnerability/GHSA-abcd-1234-5678"
    )
    assert (
        "[Open OSV advisory](https://osv.dev/vulnerability/GHSA-abcd-1234-5678)"
        in result["message"]["markdown"]
    )
    assert "jinja2 2.4.1" in result["message"]["markdown"]
    assert "example.test" not in json.dumps(result)


def test_sarif_fingerprint_does_not_hash_raw_secret_value(tmp_path: Path) -> None:
    first_secret = "sk-test-example-value"
    second_secret = "sk-test-another-value"
    first = build_report("sample", [parsed_secret_finding(tmp_path, first_secret)])
    second = build_report("sample", [parsed_secret_finding(tmp_path, second_secret)])

    first_result = json.loads(render_sarif(first))["runs"][0]["results"][0]
    second_result = json.loads(render_sarif(second))["runs"][0]["results"][0]
    assert first_result["partialFingerprints"] == second_result["partialFingerprints"]
    assert first_secret not in json.dumps(first_result)
    assert second_secret not in json.dumps(second_result)


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


def test_raw_secret_never_reaches_sarif(tmp_path: Path) -> None:
    token = "sk-test-never-render-this"
    report = build_report("sample", [parsed_secret_finding(tmp_path, token)])

    rendered = render_sarif(report)

    assert token not in rendered
    assert "[REDACTED: secret value omitted]" in rendered


def test_sarif_emits_location_only_cross_file_flow() -> None:
    from security_review.domain.models import TraceLocation

    codeql_finding = finding("codeql:flow-one", Severity.HIGH).model_copy(
        update={
            "engine": "codeql",
            "trace": (
                TraceLocation(file_path="src/input file.py", line_start=2, role="source"),
                TraceLocation(file_path="src/app.py", line_start=2, role="sink"),
            ),
        }
    )
    result = json.loads(
        render_sarif(build_report("sample", [codeql_finding]), path_prefix="checkout")
    )["runs"][0]["results"][0]

    flow = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [item["location"]["physicalLocation"]["artifactLocation"]["uri"] for item in flow] == [
        "checkout/src/input%20file.py",
        "checkout/src/app.py",
    ]
    assert [item["location"]["physicalLocation"]["region"]["startLine"] for item in flow] == [
        2,
        2,
    ]
    assert "snippet" not in json.dumps(flow)


def test_sarif_distinguishes_flows_sharing_one_sink_location() -> None:
    from security_review.domain.models import TraceLocation

    common = finding("codeql:flow-one", Severity.HIGH).model_copy(
        update={
            "engine": "codeql",
            "trace": (
                TraceLocation(file_path="src/input_a.py", line_start=1, role="source"),
                TraceLocation(file_path="src/app.py", line_start=2, role="sink"),
            ),
        }
    )
    other = common.model_copy(
        update={
            "id": "codeql:flow-two",
            "trace": (
                TraceLocation(file_path="src/input_b.py", line_start=1, role="source"),
                TraceLocation(file_path="src/app.py", line_start=2, role="sink"),
            ),
        }
    )

    results = json.loads(render_sarif(build_report("sample", [common, other])))["runs"][0][
        "results"
    ]

    assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in results}) == 2


def test_sarif_marks_incomplete_engine_execution_unsuccessful() -> None:
    from security_review.domain.models import ScanExecution

    execution = ScanExecution(
        engine="codeql",
        kind="sast",
        status="error",
        version=None,
        elapsed_ms=123,
        eligible_files=("src/app.py",),
        scanned_files=(),
        languages=("python",),
        checks=("security-extended",),
        reason="codeql_unavailable",
    )
    run = json.loads(render_sarif(build_report("sample", [], executions=(execution,))))["runs"][0]

    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["properties"]["scannerExecutions"][0]["reason"] == "codeql_unavailable"
    assert any(
        "codeql_unavailable" in item["message"]["text"]
        for item in run["invocations"][0]["toolExecutionNotifications"]
    )


def test_sarif_treats_inapplicable_engine_as_skipped() -> None:
    from security_review.domain.models import ScanExecution

    execution = ScanExecution(
        engine="codeql",
        kind="sast",
        status="skipped",
        elapsed_ms=0,
        reason="no_eligible_files",
    )
    run = json.loads(render_sarif(build_report("sample", [], executions=(execution,))))["runs"][0]

    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["scannerExecutions"][0]["status"] == "skipped"
