"""Report format selection and explicit renderer dispatch."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from security_review.domain.models import ScanReport
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif


class ReportFormat(StrEnum):
    """Supported report representations."""

    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


_Renderer = Callable[[ScanReport], str]
_RENDERERS: dict[ReportFormat, _Renderer] = {
    ReportFormat.JSON: render_json,
    ReportFormat.MARKDOWN: render_markdown,
    ReportFormat.SARIF: render_sarif,
}


def render_report(report: ScanReport, format: ReportFormat) -> str:
    """Render through a registered adapter or reject unsupported runtime values."""

    try:
        renderer = _RENDERERS[format]
    except (KeyError, TypeError) as error:
        raise ValueError(f"unsupported report format: {format}") from error
    return renderer(report)
