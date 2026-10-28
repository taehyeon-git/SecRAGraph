from __future__ import annotations

import json

from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif


def _http_finding() -> Finding:
    return Finding(
        id="zap:10021:GET:/public",
        rule_id="ZAP/10021",
        category="dast",
        severity=Severity.MEDIUM,
        http_method="GET",
        http_path="/public",
        message="Missing X-Content-Type-Options header.",
        redacted_evidence="Response header presence only.",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-693",),
        remediation="Set the response header.",
        engine="zap",
    )


def _source_finding() -> Finding:
    return Finding(
        id="source:1",
        rule_id="SOURCE/1",
        category="sast",
        severity=Severity.LOW,
        file_path="src/app.py",
        line_start=3,
        message="Source finding.",
        redacted_evidence="No source content.",
        confidence=Confidence.HIGH,
        remediation="Review the source.",
    )


def test_mixed_locations_have_stable_order_and_distinct_rendering() -> None:
    execution = ScanExecution(
        engine="zap",
        kind="dast",
        status="completed",
        elapsed_ms=15,
        eligible_endpoints=("GET /public", "GET /protected"),
        observed_alert_endpoints=("GET /public",),
        checks=("passive",),
    )
    report = build_report(
        "disposable-api", [_http_finding(), _source_finding()], executions=(execution,)
    )
    assert [item.id for item in report.findings] == ["source:1", "zap:10021:GET:/public"]

    payload = json.loads(render_json(report))
    http = payload["findings"][1]
    assert http["file_path"] is None
    assert http["line_start"] is None
    assert http["http_method"] == "GET"
    assert http["http_path"] == "/public"
    assert payload["executions"][0]["eligible_endpoints"] == ["GET /public", "GET /protected"]

    markdown = render_markdown(report)
    assert "Location: GET /public" in markdown
    assert "Location: src/app.py:3" in markdown
    assert "OpenAPI seed endpoints: 2" in markdown
    assert "Observed alert endpoints: 1" in markdown
    assert "None:None" not in markdown


def test_http_sarif_uses_logical_location_without_source_artifact() -> None:
    report = build_report("disposable-api", [_http_finding()])
    base = json.loads(render_sarif(report))["runs"][0]["results"][0]
    prefixed = json.loads(render_sarif(report, path_prefix="checkout"))["runs"][0]["results"][0]

    assert base["locations"] == [
        {"logicalLocations": [{"name": "GET /public", "fullyQualifiedName": "GET /public"}]}
    ]
    assert "physicalLocation" not in json.dumps(base)
    assert base["partialFingerprints"] == prefixed["partialFingerprints"]
    assert base["partialFingerprints"]["secragraph/httpLocationHash"]


def test_http_fingerprint_changes_with_endpoint() -> None:
    original = _http_finding()
    changed = original.model_copy(update={"http_path": "/different"})
    first = json.loads(render_sarif(build_report("api", [original])))["runs"][0]["results"][0]
    second = json.loads(render_sarif(build_report("api", [changed])))["runs"][0]["results"][0]
    assert first["partialFingerprints"] != second["partialFingerprints"]
