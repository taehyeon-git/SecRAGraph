from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_review.domain.models import Confidence, Finding, ScanExecution, Severity


def http_finding(**changes: object) -> Finding:
    values: dict[str, object] = {
        "id": "zap:10021:GET:/public",
        "rule_id": "ZAP/10021",
        "category": "dast",
        "severity": Severity.MEDIUM,
        "http_method": "GET",
        "http_path": "/public",
        "message": "A response header is missing.",
        "redacted_evidence": "Response metadata only.",
        "confidence": Confidence.HIGH,
        "remediation": "Set the response header.",
        "engine": "zap",
    }
    values.update(changes)
    return Finding.model_validate(values)


def test_http_location_has_no_source_file_or_line() -> None:
    finding = http_finding()

    assert finding.file_path is None
    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.http_method == "GET"
    assert finding.http_path == "/public"


@pytest.mark.parametrize(
    "changes",
    [
        {"file_path": "app.py", "line_start": 1},
        {"file_path": "app.py"},
        {"line_start": 1},
        {"line_end": 2},
        {"http_method": None},
        {"http_path": None},
        {"http_path": "https://example.test/public"},
        {"http_path": "//example.test/public"},
        {"http_path": "/public?token=secret"},
        {"http_path": "/public#fragment"},
        {"http_path": "/public\nheader: secret"},
        {"http_method": "get"},
    ],
)
def test_http_location_rejects_source_fields_or_unsafe_parts(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        http_finding(**changes)


def test_source_location_still_requires_a_positive_line() -> None:
    values = http_finding().model_dump()
    values.update({"http_method": None, "http_path": None, "file_path": "src/app.py"})
    with pytest.raises(ValidationError):
        Finding.model_validate(values)


def test_dast_execution_has_bounded_http_operation_coverage() -> None:
    execution = ScanExecution(
        engine="zap",
        kind="dast",
        status="completed",
        elapsed_ms=120,
        eligible_endpoints=("GET /public", "HEAD /health"),
        observed_alert_endpoints=("GET /public",),
        checks=("passive",),
    )

    assert execution.eligible_endpoints == ("GET /public", "HEAD /health")
    assert execution.observed_alert_endpoints == ("GET /public",)


@pytest.mark.parametrize(
    "endpoint",
    [
        "get /public",
        "GET https://example.test/public",
        "GET //example.test/public",
        "GET /x?key=a",
        "GET /x#f",
        "GET /bad\nname",
    ],
)
def test_dast_execution_rejects_unsafe_operation_labels(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        ScanExecution(
            engine="zap",
            kind="dast",
            status="completed",
            elapsed_ms=1,
            eligible_endpoints=(endpoint,),
        )


def test_dast_execution_rejects_duplicate_operations() -> None:
    with pytest.raises(ValidationError):
        ScanExecution(
            engine="zap",
            kind="dast",
            status="completed",
            elapsed_ms=1,
            eligible_endpoints=("GET /public", "GET /public"),
        )
