"""LangGraph application boundary for a trusted local container image tar."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import security_review.container_image as container_image
from security_review.container_image import ImageGateIdentity
from security_review.domain.models import ScanReport
from security_review.intelligence.dynamic_cwe import CweEvidenceProvider
from security_review.orchestrator.scan_graph import (
    ScanGraphServices,
    ScanState,
    ScanWorkflowError,
    build_scan_graph,
)
from security_review.ports import SecurityDocumentRetriever


@dataclass(frozen=True, slots=True)
class ImageReview:
    """One normalized report and the SBOM/gate data from the same tar."""

    report: ScanReport
    sbom_bytes: bytes
    gate_identities: tuple[ImageGateIdentity, ...]


def scan_image_path(
    tar_path: Path,
    *,
    expected_local_id: str,
    trivy_binary: str,
    cache_dir: Path,
    cwe_evidence: CweEvidenceProvider | None = None,
    retriever: SecurityDocumentRetriever | None = None,
) -> ImageReview:
    """Inspect a trusted tar, then enrich its findings through the shared graph."""

    result = container_image.scan_image_tar(
        tar_path,
        expected_local_id=expected_local_id,
        trivy_binary=trivy_binary,
        cache_dir=cache_dir,
    )
    if (
        result.execution.kind != "container"
        or result.execution.status != "completed"
        or result.execution.image_id is None
        or any(finding.image_id != result.execution.image_id for finding in result.findings)
    ):
        raise ScanWorkflowError("image_identity_mismatch")
    graph = build_scan_graph(ScanGraphServices(cwe_evidence=cwe_evidence, retriever=retriever))
    state = cast(
        ScanState,
        graph.invoke(
            {
                "findings": result.findings,
                "warnings": result.warnings,
                "executions": (result.execution,),
                "target_name": tar_path.name,
            }
        ),
    )
    report = state.get("report")
    if not isinstance(report, ScanReport):
        raise ScanWorkflowError("missing_report")
    return ImageReview(
        report=report,
        sbom_bytes=result.sbom_bytes,
        gate_identities=result.gate_identities,
    )
