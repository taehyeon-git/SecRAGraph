"""DAST application boundary shared by the CLI and automated evidence run."""

from __future__ import annotations

from typing import cast

from security_review.dast.runner import run_zap_api_scan
from security_review.domain.models import ScanReport
from security_review.intelligence.dynamic_cwe import CweEvidenceProvider
from security_review.orchestrator.scan_graph import (
    ScanGraphServices,
    ScanState,
    ScanWorkflowError,
    build_scan_graph,
)
from security_review.ports import SecurityDocumentRetriever


def scan_dast_container(
    container: str,
    port: int,
    openapi_path: str,
    *,
    auth_header_env: str | None = None,
    active: bool = False,
    cwe_evidence: CweEvidenceProvider | None = None,
    retriever: SecurityDocumentRetriever | None = None,
    enrichment_budget_seconds: float = 30.0,
) -> ScanReport:
    """Run one scoped ZAP scan, then enrich and report its HTTP findings."""

    result = run_zap_api_scan(
        container,
        port,
        openapi_path,
        auth_header_env=auth_header_env,
        active=active,
    )
    graph = build_scan_graph(ScanGraphServices(cwe_evidence=cwe_evidence, retriever=retriever))
    state = cast(
        ScanState,
        graph.invoke(
            {
                "findings": result.findings,
                "warnings": result.warnings,
                "executions": (result.execution, *result.supplemental_executions),
                "target_name": container,
                "enrichment_budget_seconds": enrichment_budget_seconds,
            }
        ),
    )
    report = state.get("report")
    if not isinstance(report, ScanReport):
        raise ScanWorkflowError("missing_report")
    return report
