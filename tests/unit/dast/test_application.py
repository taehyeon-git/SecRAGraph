"""DAST uses one ZAP execution and the canonical LangGraph report."""

from __future__ import annotations

import pytest

from security_review.dast.application import scan_dast_container
from security_review.dast.runner import DastScanResult
from security_review.domain.models import Confidence, Finding, ScanExecution, ScanStatus, Severity


def test_dast_application_preserves_http_findings_coverage_and_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = Finding(
        id="zap-10021-ready",
        rule_id="ZAP-10021",
        category="security-headers",
        severity=Severity.LOW,
        http_method="GET",
        http_path="/ready",
        message="X-Content-Type-Options missing",
        redacted_evidence="Response metadata only.",
        confidence=Confidence.MEDIUM,
        remediation="Set X-Content-Type-Options.",
        engine="zap",
    )
    execution = ScanExecution(
        engine="zap",
        kind="dast",
        status="completed",
        elapsed_ms=150,
        eligible_endpoints=("GET /ready",),
        observed_alert_endpoints=("GET /ready",),
        checks=("openapi-passive",),
    )
    calls: list[tuple[str, int, str, str | None]] = []

    def fake_runner(
        container: str,
        port: int,
        openapi_path: str,
        *,
        auth_header_env: str | None = None,
    ) -> DastScanResult:
        calls.append((container, port, openapi_path, auth_header_env))
        return DastScanResult((finding,), ("dast_passive_only",), execution)

    monkeypatch.setattr("security_review.dast.application.run_zap_api_scan", fake_runner)
    report = scan_dast_container("fixture", 8000, "/openapi.json", auth_header_env="TOKEN_ENV")

    assert calls == [("fixture", 8000, "/openapi.json", "TOKEN_ENV")]
    assert report.findings == (finding,)
    assert report.executions == (execution,)
    assert report.warnings == ("dast_passive_only",)
    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS


def test_dast_application_keeps_error_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    execution = ScanExecution(
        engine="zap",
        kind="dast",
        status="error",
        elapsed_ms=10,
        reason="dast_zap_failed",
    )
    monkeypatch.setattr(
        "security_review.dast.application.run_zap_api_scan",
        lambda *args, **kwargs: DastScanResult((), ("dast_zap_failed",), execution),
    )

    report = scan_dast_container("fixture", 8000, "/openapi.json")

    assert report.summary.total == 0
    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS
    assert report.executions[0].status == "error"
