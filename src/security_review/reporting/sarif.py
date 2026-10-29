"""Dependency-free SARIF 2.1.0 rendering for GitHub Code Scanning."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

from security_review.domain.models import Finding, ScanReport, Severity, TraceLocation

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _descriptor(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {
            "text": (
                "Vulnerable locked dependency reported by OSV.dev."
                if finding.rule_id == "OSV001"
                else finding.message
            )
        },
        "help": {
            "text": finding.remediation,
            "markdown": finding.remediation,
        },
        "properties": {
            "category": finding.category,
            "tags": ["security", *finding.cwe_ids],
        },
    }


def _region(finding: Finding) -> dict[str, int]:
    if finding.line_start is None:
        raise ValueError("source finding requires a line")
    region = {"startLine": finding.line_start}
    if finding.line_end is not None:
        region["endLine"] = finding.line_end
    return region


def _fingerprint(finding: Finding) -> str:
    # A source-free location identity avoids both evidence-derived hashes and
    # occurrence shifts when another finding is added earlier in the file.
    if finding.http_path is not None:
        payload = f"{finding.rule_id}\0{finding.http_method}\0{finding.http_path}\0{finding.id}"
        return sha256(payload.encode()).hexdigest()
    if finding.git_commit is not None:
        payload = (
            f"{finding.rule_id}\0{finding.git_commit}\0{finding.file_path}"
            f"\0{finding.line_start}\0{finding.id}"
        )
        return sha256(payload.encode()).hexdigest()
    payload = f"{finding.rule_id}\0{finding.file_path}\0{finding.line_start}"
    if finding.rule_id == "OSV001" or finding.engine != "secragraph" or finding.trace:
        # Distinct advisories or flows can share a sink location.
        payload += f"\0{finding.id}"
    encoded = payload.encode()
    return sha256(encoded).hexdigest()


def _flow_location(location: TraceLocation, path_prefix: str) -> dict[str, Any]:
    source_path = (PurePosixPath(path_prefix) / location.file_path).as_posix()
    region = {"startLine": location.line_start}
    if location.line_end is not None:
        region["endLine"] = location.line_end
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": quote(source_path, safe="/-._~")},
                "region": region,
            }
        },
        "properties": {"role": location.role},
    }


def _osv_advisory_url(finding: Finding) -> str | None:
    if finding.rule_id != "OSV001":
        return None
    for reference in finding.references:
        url = reference.source_url
        if not url or len(url) > 300:
            continue
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if (
            parsed.scheme == "https"
            and parsed.netloc == "osv.dev"
            and re.fullmatch(r"/vulnerability/[A-Za-z0-9._-]{1,128}", parsed.path)
            and not parsed.query
            and not parsed.fragment
        ):
            return url
    return None


def _escaped_markdown_text(value: str) -> str:
    flattened = " ".join(value.split())
    return re.sub(r"([\\`*_\[\]()<>])", r"\\\1", flattened)


def _result(
    finding: Finding, rule_index: int, path_prefix: str, fingerprint: str
) -> dict[str, Any]:
    message = {"text": finding.message}
    properties = {
        "findingId": finding.id,
        "engine": finding.engine,
        "category": finding.category,
        "confidence": finding.confidence.value,
        "cweIds": list(finding.cwe_ids),
        "redactedEvidence": finding.redacted_evidence,
        "severity": finding.severity.value,
    }
    osv_url = _osv_advisory_url(finding)
    if osv_url is not None:
        message["markdown"] = (
            f"{_escaped_markdown_text(finding.message)} [Open OSV advisory]({osv_url})"
        )
        properties["osvAdvisoryUrl"] = osv_url
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": message,
        "properties": properties,
    }
    if finding.http_path is not None:
        name = f"{finding.http_method} {finding.http_path}"
        result["locations"] = [{"logicalLocations": [{"name": name, "fullyQualifiedName": name}]}]
        result["partialFingerprints"] = {"secragraph/httpLocationHash": fingerprint}
    elif finding.git_commit is not None:
        if finding.file_path is None or finding.line_start is None:
            raise ValueError("historical finding requires a source path and line")
        location = f"{finding.file_path}:{finding.line_start}@{finding.git_commit}"
        result["locations"] = [
            {"logicalLocations": [{"name": location, "fullyQualifiedName": location}]}
        ]
        result["properties"]["gitCommit"] = finding.git_commit
        result["partialFingerprints"] = {"secragraph/historyLocationHash": fingerprint}
    else:
        if finding.file_path is None:
            raise ValueError("source finding requires a file path")
        source_path = (PurePosixPath(path_prefix) / finding.file_path).as_posix()
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(source_path, safe="/-._~")},
                    "region": _region(finding),
                }
            }
        ]
        result["partialFingerprints"] = {"primaryLocationLineHash": fingerprint}
    if finding.trace:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            _flow_location(location, path_prefix) for location in finding.trace
                        ]
                    }
                ]
            }
        ]
    return result


def render_sarif(report: ScanReport, *, path_prefix: str = "") -> str:
    """Render one SARIF run with stable rule indexes and finding fingerprints."""

    prefix = PurePosixPath(path_prefix.replace("\\", "/"))
    if prefix.is_absolute() or ".." in prefix.parts or (prefix.parts and ":" in prefix.parts[0]):
        raise ValueError("SARIF path prefix must be relative")

    by_rule: dict[str, Finding] = {}
    for finding in report.findings:
        by_rule.setdefault(finding.rule_id, finding)
    rule_ids = sorted(by_rule)
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        results.append(
            _result(
                finding,
                rule_indexes[finding.rule_id],
                prefix.as_posix(),
                _fingerprint(finding),
            )
        )
    notifications = [
        {"level": "warning", "message": {"text": warning}} for warning in report.warnings
    ]
    for execution in report.executions:
        if execution.status not in {"completed", "skipped"}:
            notification = f"{execution.engine} ({execution.kind}): {execution.status}"
            if execution.reason is not None:
                notification += f" ({execution.reason})"
            notifications.append(
                {
                    "level": "error" if execution.status == "error" else "warning",
                    "message": {"text": notification},
                }
            )
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecRAGraph",
                        "semanticVersion": report.tool_version,
                        "rules": [_descriptor(by_rule[rule_id]) for rule_id in rule_ids],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": all(
                            execution.status in {"completed", "skipped"}
                            for execution in report.executions
                        ),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "properties": {
                    "scannerExecutions": [
                        execution.model_dump(mode="json") for execution in report.executions
                    ]
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
