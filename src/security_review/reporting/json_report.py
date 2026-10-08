"""JSON rendering for canonical security-review reports."""

from security_review.domain.models import ScanReport


def render_json(report: ScanReport) -> str:
    """Serialize a report using Pydantic's JSON-safe representation."""

    return report.model_dump_json(indent=2)
