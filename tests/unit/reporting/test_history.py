from __future__ import annotations

import json

from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


def _finding(commit: str) -> Finding:
    return Finding(
        id=f"gitleaks:{commit}:settings.py:7",
        rule_id="gitleaks:generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        file_path="settings.py",
        line_start=7,
        git_commit=commit,
        message="Secret-like value appeared in Git history.",
        redacted_evidence="[REDACTED: secret value omitted]",
        confidence=Confidence.HIGH,
        remediation="Rotate the credential.",
        engine="gitleaks",
    )


def test_historical_sarif_uses_logical_revision_location_and_distinct_fingerprints() -> None:
    report = build_report("repo", [_finding(COMMIT_B), _finding(COMMIT_A)])
    run = json.loads(render_sarif(report, path_prefix="checkout"))["runs"][0]
    results = run["results"]

    assert [finding.git_commit for finding in report.findings] == [COMMIT_A, COMMIT_B]
    assert len(results) == 2
    assert results[0]["properties"]["gitCommit"] == COMMIT_A
    assert results[1]["properties"]["gitCommit"] == COMMIT_B
    assert "physicalLocation" not in json.dumps(results)
    assert "primaryLocationLineHash" not in json.dumps(results)
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]
    assert "settings.py" in results[0]["locations"][0]["logicalLocations"][0]["name"]
    assert "checkout" not in json.dumps(results)


def test_historical_markdown_and_json_show_commit_and_honest_coverage() -> None:
    execution = ScanExecution(
        engine="gitleaks",
        kind="secret",
        status="completed",
        elapsed_ms=10,
        revision_base=COMMIT_A,
        revision_head=COMMIT_B,
        selected_commit_count=3,
        checks=("git-history",),
    )
    report = build_report("repo", [_finding(COMMIT_B)], executions=(execution,))

    markdown = render_markdown(report)
    payload = json.loads(render_json(report))
    assert f"Git commit: {COMMIT_B}" in markdown
    assert f"Base revision: {COMMIT_A}" in markdown
    assert f"Head revision: {COMMIT_B}" in markdown
    assert "Selected commits: 3" in markdown
    assert "Submitted files" not in markdown
    assert "Confirmed finding paths" not in markdown
    assert payload["findings"][0]["git_commit"] == COMMIT_B
    assert payload["executions"][0]["selected_commit_count"] == 3


def test_full_history_execution_displays_reachability_without_implied_base() -> None:
    report = build_report(
        "repo",
        [],
        executions=(
            ScanExecution(
                engine="gitleaks",
                kind="secret",
                status="completed",
                elapsed_ms=10,
                revision_head=COMMIT_A,
                selected_commit_count=7,
            ),
        ),
    )

    markdown = render_markdown(report)
    assert "Base revision: Full reachable history" in markdown
    assert "Selected commits: 7" in markdown


def test_failed_history_execution_does_not_claim_file_coverage() -> None:
    report = build_report(
        "repo",
        [],
        executions=(
            ScanExecution(
                engine="gitleaks-history",
                kind="secret",
                status="error",
                elapsed_ms=10,
                reason="history_timeout",
            ),
        ),
    )

    markdown = render_markdown(report)

    assert "Git history range: unavailable" in markdown
    assert "Eligible files" not in markdown
    assert "Scanned files" not in markdown
