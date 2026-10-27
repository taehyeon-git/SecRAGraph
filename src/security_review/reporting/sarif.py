"""Dependency-free SARIF 2.1.0 rendering for GitHub Code Scanning."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

from security_review.domain.models import Finding, ScanReport, Severity

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
    region = {"startLine": finding.line_start}
    if finding.line_end is not None:
        region["endLine"] = finding.line_end
    return region


def _fingerprint(finding: Finding) -> str:
    # A source-free location identity avoids both evidence-derived hashes and
    # occurrence shifts when another finding is added earlier in the file.
    payload = f"{finding.rule_id}\0{finding.file_path}\0{finding.line_start}"
    if finding.rule_id == "OSV001":
        # A lockfile has many coordinates and advisories but one stable location.
        payload += f"\0{finding.id}"
    encoded = payload.encode()
    return sha256(encoded).hexdigest()


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
    source_path = (PurePosixPath(path_prefix) / finding.file_path).as_posix()
    message = {"text": finding.message}
    properties = {
        "findingId": finding.id,
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
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": message,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(source_path, safe="/-._~"),
                    },
                    "region": _region(finding),
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        "properties": properties,
    }


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
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications,
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
