import json
from typing import cast

import pytest

from security_review.domain.models import Confidence, Finding, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.types import ReportFormat, render_report


def sample_finding() -> Finding:
    return Finding(
        id="GITLEAKS:stable",
        rule_id="GITLEAKS/generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        file_path="src/settings.py",
        line_start=7,
        message="Secret-like value detected.",
        redacted_evidence="OPENAI_API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-798",),
        remediation="Load the replacement from a secret store.",
        engine="gitleaks",
    )


def test_json_and_markdown_use_same_finding_id() -> None:
    finding = sample_finding()
    report = build_report("sample", [finding])

    assert finding.id in render_json(report)
    assert finding.id in render_markdown(report)


def test_json_is_a_canonical_report_serialization() -> None:
    report = build_report("sample", [sample_finding()])

    payload = json.loads(render_json(report))

    assert payload["summary"]["total"] == 1
    assert payload["risk"]["level"] == "high"
    assert payload["findings"][0]["redacted_evidence"].endswith("***REDACTED***")


def test_markdown_contains_risk_remediation_and_empty_reference_message() -> None:
    report = build_report("sample", [sample_finding()])

    rendered = render_markdown(report)

    assert "HIGH" in rendered
    assert "OPENAI_API_KEY = \\*\\*\\*REDACTED\\*\\*\\*" in rendered
    assert "Load the replacement from a secret store." in rendered
    assert "No evidence references available." in rendered


def test_markdown_escapes_untrusted_fields() -> None:
    finding = sample_finding().model_copy(
        update={"message": "<script>alert(1)</script> | injected"}
    )
    report = build_report("<b>sample</b>", [finding], ["<img src=x> | warning"])

    rendered = render_markdown(report)

    assert "<script>" not in rendered
    assert "<img" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "\\| injected" in rendered


def test_render_report_dispatches_explicit_formats() -> None:
    report = build_report("sample", [sample_finding()])

    assert render_report(report, ReportFormat.JSON) == render_json(report)
    assert render_report(report, ReportFormat.MARKDOWN) == render_markdown(report)
    with pytest.raises(ValueError, match="unsupported report format"):
        render_report(report, cast(ReportFormat, "xml"))


def test_report_json_and_markdown_show_engine_coverage_and_source_to_sink() -> None:
    from security_review.domain.models import ScanExecution, TraceLocation

    finding = sample_finding().model_copy(
        update={
            "engine": "codeql",
            "trace": (
                TraceLocation(file_path="src/routes.py", line_start=4, role="source"),
                TraceLocation(file_path="src/settings.py", line_start=7, role="sink"),
            ),
        }
    )
    execution = ScanExecution(
        engine="codeql",
        kind="sast",
        status="completed",
        version="2.23.0",
        elapsed_ms=321,
        eligible_files=("src/routes.py", "src/settings.py"),
        scanned_files=("src/routes.py", "src/settings.py"),
        languages=("python",),
        checks=("security-extended",),
    )
    report = build_report("sample", [finding], executions=(execution,))

    payload = json.loads(render_json(report))
    rendered = render_markdown(report)
    assert payload["executions"][0]["engine"] == "codeql"
    assert payload["executions"][0]["scanned_files"] == ["src/routes.py", "src/settings.py"]
    assert payload["findings"][0]["trace"][0] == {
        "file_path": "src/routes.py",
        "line_start": 4,
        "line_end": None,
        "role": "source",
    }
    assert "Scan coverage" in rendered
    assert "security-extended" in rendered
    assert "src/routes.py:4" in rendered
    assert "src/settings.py:7" in rendered


def test_markdown_distinguishes_gitleaks_submitted_files_from_confirmed_paths() -> None:
    from security_review.domain.models import ScanExecution

    execution = ScanExecution(
        engine="gitleaks",
        kind="secret",
        status="completed",
        version="8.30.1",
        elapsed_ms=100,
        eligible_files=("src/app.py",),
        scanned_files=(),
    )
    rendered = render_markdown(build_report("sample", [], executions=(execution,)))

    assert "Submitted files: 1" in rendered
    assert "Confirmed finding paths: 0" in rendered
    assert "does not provide an inspected-file inventory" in rendered
    assert "Scanned files: 0" not in rendered
