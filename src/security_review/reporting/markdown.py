"""Human-readable Markdown rendering with untrusted fields escaped."""

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from security_review.domain.models import Finding, ScanReport, SourceReference

_MARKDOWN_CONTROL = re.compile(r"([\\`*\[\]#|>])")


def _escape(value: object) -> str:
    normalized = str(value).replace("\r", " ").replace("\n", " ")
    escaped_html = html.escape(normalized, quote=True)
    return _MARKDOWN_CONTROL.sub(r"\\\1", escaped_html)


def _safe_url(reference: SourceReference) -> str | None:
    if reference.source_url is None:
        return None
    parsed = urlparse(reference.source_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return _escape(reference.source_url)


def _render_reference(reference: SourceReference) -> str:
    details = [_escape(reference.title)]
    if reference.section:
        details.append(f"section {_escape(reference.section)}")
    if reference.page is not None:
        details.append(f"page {reference.page}")
    url = _safe_url(reference)
    if url:
        details.append(url)
    return " — ".join(details)


def _render_finding(finding: Finding) -> list[str]:
    lines = [
        f"### {_escape(finding.id)}",
        "",
        f"- Rule: {_escape(finding.rule_id)}",
        f"- Severity: {_escape(finding.severity.value.upper())}",
        f"- Location: {_escape(finding.file_path)}:{finding.line_start}",
        f"- CWE: {_escape(', '.join(finding.cwe_ids) or 'Not mapped')}",
        f"- Message: {_escape(finding.message)}",
        f"- Evidence: {_escape(finding.redacted_evidence)}",
        f"- Remediation: {_escape(finding.remediation)}",
        "- Evidence references:",
    ]
    if finding.references:
        lines.extend(f"  - {_render_reference(reference)}" for reference in finding.references)
    else:
        lines.append("  - No evidence references available.")
    lines.append("")
    return lines


def render_markdown(report: ScanReport) -> str:
    """Render a canonical report without trusting any scanned or supplied text."""

    lines = [
        "# SecRAGraph Security Review",
        "",
        f"- Target: {_escape(report.target_name)}",
        f"- Scan ID: {_escape(report.scan_id)}",
        f"- Status: {_escape(report.status.value)}",
        f"- Created: {_escape(report.created_at.isoformat())}",
        "",
        "## Risk summary",
        "",
        f"- Risk level: {_escape(report.risk.level.value.upper())}",
        f"- Risk score: {report.risk.score}",
        f"- Findings: {report.summary.total}",
        "",
    ]
    if report.warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {_escape(warning)}" for warning in report.warnings)
        lines.append("")
    lines.extend(["## Findings", ""])
    if not report.findings:
        lines.extend(["No findings.", ""])
    else:
        for finding in report.findings:
            lines.extend(_render_finding(finding))
    return "\n".join(lines).rstrip() + "\n"
