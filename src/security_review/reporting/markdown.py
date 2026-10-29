"""Human-readable Markdown rendering with untrusted fields escaped."""

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from security_review.domain.models import Finding, ScanExecution, ScanReport, SourceReference

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
    if finding.http_path is not None:
        location = f"{finding.http_method} {finding.http_path}"
    elif finding.image_resource is not None:
        location = finding.image_resource
    else:
        location = f"{finding.file_path}:{finding.line_start}"
    lines = [
        f"### {_escape(finding.id)}",
        "",
        f"- Rule: {_escape(finding.rule_id)}",
        f"- Engine: {_escape(finding.engine)}",
        f"- Severity: {_escape(finding.severity.value.upper())}",
        f"- Location: {_escape(location)}",
        f"- CWE: {_escape(', '.join(finding.cwe_ids) or 'Not mapped')}",
        f"- Message: {_escape(finding.message)}",
        f"- Evidence: {_escape(finding.redacted_evidence)}",
        f"- Remediation: {_escape(finding.remediation)}",
    ]
    if finding.git_commit is not None:
        lines.insert(6, f"- Git commit: {_escape(finding.git_commit)}")
    if finding.image_id is not None:
        lines.extend(
            [
                f"- Image config digest: {_escape(finding.image_id)}",
                f"- Upstream severity: {_escape(finding.upstream_severity)}",
                f"- Severity source: {_escape(finding.severity_source or 'Unknown')}",
            ]
        )
    if finding.trace:
        lines.append("- Source-to-sink trace:")
        lines.extend(
            f"  - {_escape(location.role)}: {_escape(location.file_path)}:{location.line_start}"
            for location in finding.trace
        )
    lines.append("- Evidence references:")
    if finding.references:
        lines.extend(f"  - {_render_reference(reference)}" for reference in finding.references)
    else:
        lines.append("  - No evidence references available.")
    lines.append("")
    return lines


def _render_execution(execution: ScanExecution) -> list[str]:
    files = ", ".join(_escape(path) for path in execution.scanned_files) or "None"
    languages = ", ".join(_escape(language) for language in execution.languages) or "None"
    checks = ", ".join(_escape(check) for check in execution.checks) or "None"
    lines = [
        f"### {_escape(execution.engine)} ({_escape(execution.kind)})",
        "",
        f"- Status: {_escape(execution.status)}",
        f"- Version: {_escape(execution.version or 'Unknown')}",
        f"- Elapsed: {execution.elapsed_ms} ms",
    ]
    if execution.kind == "container":
        lines.extend(
            [
                f"- Image config digest: {_escape(execution.image_id or 'Unavailable')}",
                f"- Local image ID: {_escape(execution.image_local_id or 'Unavailable')}",
                f"- Image tar SHA-256: {_escape(execution.image_tar_sha256 or 'Unavailable')}",
                f"- Vulnerability records: {_escape(execution.image_vulnerability_count)}",
                f"- Image configuration records: {_escape(execution.image_config_count)}",
                f"- SBOM SHA-256: {_escape(execution.sbom_sha256 or 'Unavailable')}",
                f"- SBOM components: {_escape(execution.sbom_component_count)}",
                "- Vulnerability DB updated: "
                f"{_escape(execution.image_db_updated_at or 'Unavailable')}",
                "- Container coverage does not claim source files or HTTP endpoints.",
            ]
        )
    elif execution.kind == "dast":
        eligible = ", ".join(_escape(endpoint) for endpoint in execution.eligible_endpoints[:50])
        observed = ", ".join(
            _escape(endpoint) for endpoint in execution.observed_alert_endpoints[:50]
        )
        if len(execution.eligible_endpoints) > 50:
            eligible += f" (+{len(execution.eligible_endpoints) - 50} more)"
        if len(execution.observed_alert_endpoints) > 50:
            observed += f" (+{len(execution.observed_alert_endpoints) - 50} more)"
        lines.extend(
            [
                f"- OpenAPI seed endpoints: {len(execution.eligible_endpoints)}",
                f"- Seed operations: {eligible or 'None'}",
                f"- Observed alert endpoints: {len(execution.observed_alert_endpoints)}",
                f"- Alert locations: {observed or 'None'}",
                "- Seeds and alert locations do not inventory every request sent; "
                "redirects within the isolated network may be followed.",
            ]
        )
    elif execution.engine == "gitleaks-history" or execution.revision_head is not None:
        if execution.revision_head is None:
            lines.append("- Git history range: unavailable")
        else:
            base_label = execution.revision_base or "Full reachable history"
            lines.extend(
                [
                    f"- Base revision: {_escape(base_label)}",
                    f"- Head revision: {_escape(execution.revision_head)}",
                    f"- Selected commits: {execution.selected_commit_count}",
                ]
            )
        lines.append("- Git history inspection does not provide an inspected-file inventory.")
    elif execution.engine == "gitleaks":
        lines.extend(
            [
                f"- Submitted files: {len(execution.eligible_files)}",
                f"- Confirmed finding paths: {len(execution.scanned_files)}",
                f"- Finding paths: {files}",
                "- Gitleaks does not provide an inspected-file inventory.",
            ]
        )
    else:
        lines.extend(
            [
                f"- Eligible files: {len(execution.eligible_files)}",
                f"- Scanned files: {len(execution.scanned_files)}",
                f"- Files checked: {files}",
            ]
        )
    lines.extend([f"- Languages: {languages}", f"- Checks: {checks}"])
    if execution.reason is not None:
        lines.append(f"- Reason: {_escape(execution.reason)}")
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
    if report.executions:
        lines.extend(["## Scan coverage", ""])
        for execution in report.executions:
            lines.extend(_render_execution(execution))
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
