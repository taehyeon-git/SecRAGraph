"""Persisted scan retrieval and report rendering endpoints."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from security_review.api.dependencies import get_report_repository
from security_review.api.errors import APIError
from security_review.api.schemas import ScanReport
from security_review.ports import ReportRepository
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif

router = APIRouter(prefix="/v1/scans", tags=["reports"])


def _load_report(repository: ReportRepository, scan_id: UUID) -> ScanReport:
    report = repository.get(scan_id)
    if report is None:
        raise APIError(404, "scan_not_found", "The requested scan does not exist.")
    return report


@router.get("/{scan_id}", response_model=ScanReport)
def get_scan(
    scan_id: UUID,
    repository: Annotated[ReportRepository, Depends(get_report_repository)],
) -> ScanReport:
    """Return one canonical persisted report as JSON."""

    return _load_report(repository, scan_id)


@router.get("/{scan_id}/report")
def get_rendered_report(
    scan_id: UUID,
    repository: Annotated[ReportRepository, Depends(get_report_repository)],
    report_format: Annotated[
        Literal["markdown", "sarif"],
        Query(alias="format"),
    ] = "markdown",
) -> Response:
    """Render Markdown or SARIF from the exact persisted report."""

    report = _load_report(repository, scan_id)
    if report_format == "markdown":
        return Response(content=render_markdown(report), media_type="text/markdown")
    return Response(content=render_sarif(report), media_type="application/sarif+json")
