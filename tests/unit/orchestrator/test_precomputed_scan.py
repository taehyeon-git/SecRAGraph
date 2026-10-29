"""Precomputed DAST findings keep their scan provenance through LangGraph."""

from __future__ import annotations

import math

import pytest

from security_review.domain.models import Confidence, Finding, ScanExecution, ScanStatus, Severity
from security_review.intelligence.models import DocumentChunk
from security_review.orchestrator.scan_graph import ScanGraphServices, build_scan_graph


def _finding() -> Finding:
    return Finding(
        id="demo-1",
        rule_id="DEMO001",
        category="security-headers",
        severity=Severity.LOW,
        file_path="src/demo.py",
        line_start=1,
        message="A header is absent.",
        redacted_evidence="Response metadata only.",
        confidence=Confidence.MEDIUM,
        remediation="Add the header.",
    )


def _execution() -> ScanExecution:
    return ScanExecution(
        engine="zap",
        kind="sast",
        status="partial",
        elapsed_ms=42,
        reason="test_partial",
    )


def test_precomputed_scan_preserves_warnings_and_execution_status() -> None:
    finding = _finding()
    execution = _execution()

    result = build_scan_graph(ScanGraphServices()).invoke(
        {
            "findings": (finding,),
            "warnings": ("dast_scope_limited",),
            "executions": (execution,),
            "target_name": "disposable-api",
            "enrichment_budget_seconds": 10.0,
        }
    )

    report = result["report"]
    assert report.findings == (finding,)
    assert report.warnings == ("dast_scope_limited",)
    assert report.executions == (execution,)
    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS


class _AdvancingRetriever:
    def __init__(self, clock_value: list[float]) -> None:
        self.clock_value = clock_value
        self.calls = 0

    def search(self, query: str, *, limit: int) -> tuple[()]:
        self.calls += 1
        self.clock_value[0] = 2.0
        return ()


def test_precomputed_scan_enrichment_honors_its_own_budget() -> None:
    now = [0.0]
    retriever = _AdvancingRetriever(now)
    finding = _finding()

    result = build_scan_graph(ScanGraphServices(retriever=retriever)).invoke(
        {
            "findings": (finding,),
            "target_name": "disposable-api",
            "clock": lambda: now[0],
            "enrichment_budget_seconds": 1.0,
        }
    )

    assert retriever.calls == 1
    assert result["report"].findings == (finding,)
    assert "processing_time_limit_exceeded" in result["report"].warnings
    assert result["report"].status is ScanStatus.COMPLETED_WITH_WARNINGS


@pytest.mark.parametrize("budget", [0, -1, True, math.nan, math.inf, 301])
def test_precomputed_scan_rejects_invalid_enrichment_budget(budget: object) -> None:
    with pytest.raises(ValueError, match="enrichment_budget_seconds"):
        build_scan_graph(ScanGraphServices()).invoke(
            {
                "findings": (_finding(),),
                "enrichment_budget_seconds": budget,
            }
        )


def test_rag_enrichment_preserves_http_location() -> None:
    finding = Finding(
        id="zap-10021-get-ready",
        rule_id="ZAP-10021",
        category="security-headers",
        severity=Severity.LOW,
        http_method="GET",
        http_path="/ready",
        message="X-Content-Type-Options is missing.",
        redacted_evidence="Response metadata only.",
        confidence=Confidence.MEDIUM,
        cwe_ids=("CWE-693",),
        remediation="Set the header.",
        engine="zap",
    )

    class _Retriever:
        def search(self, query: str, *, limit: int) -> tuple[DocumentChunk, ...]:
            return (
                DocumentChunk(
                    id="cwe-693",
                    text="Protection mechanism failure guidance.",
                    title="CWE-693",
                    score=0.9,
                ),
            )

    result = build_scan_graph(ScanGraphServices(retriever=_Retriever())).invoke(
        {"findings": (finding,), "target_name": "disposable-api"}
    )

    enriched = result["report"].findings[0]
    assert enriched.http_method == "GET"
    assert enriched.http_path == "/ready"
    assert enriched.file_path is None
    assert enriched.references[0].id == "cwe-693"
