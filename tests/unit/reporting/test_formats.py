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
        id="SEC001:stable",
        rule_id="SEC001",
        category="secret",
        severity=Severity.HIGH,
        file_path="src/settings.py",
        line_start=7,
        message="Secret-like value detected.",
        redacted_evidence="OPENAI_API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-798",),
        remediation="Load the replacement from a secret store.",
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
