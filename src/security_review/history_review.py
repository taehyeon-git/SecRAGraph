"""Shared LangGraph application entry point for trusted Git history scans."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from security_review.domain.models import ScanReport
from security_review.orchestrator.scan_graph import (
    ScanGraphServices,
    ScanState,
    ScanWorkflowError,
    build_scan_graph,
)


def scan_history_path(
    root: Path,
    *,
    base_sha: str | None = None,
    head_sha: str | None = None,
    binary: str = "gitleaks",
) -> ScanReport:
    """Inspect selected history once, then build the canonical report.

    The history engine handles selection and redaction before any finding reaches
    the graph. Callers must provide a trusted local checkout, never an upload.
    """

    from security_review.history import scan_git_history

    result = scan_git_history(root, base_sha=base_sha, head_sha=head_sha, binary=binary)
    graph = build_scan_graph(ScanGraphServices())
    state = cast(
        ScanState,
        graph.invoke(
            {
                "findings": result.findings,
                "warnings": result.warnings,
                "executions": (result.execution,),
                "target_name": root.name,
            }
        ),
    )
    report = state.get("report")
    if not isinstance(report, ScanReport):
        raise ScanWorkflowError("missing_report")
    return report
