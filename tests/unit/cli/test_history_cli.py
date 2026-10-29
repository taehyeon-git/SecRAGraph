"""History CLI keeps a trusted checkout separate from upload scanning."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import security_review.cli as cli
from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.reporting.builder import build_report


def _history_finding() -> Finding:
    return Finding(
        id="gitleaks-history:example",
        rule_id="GITLEAKS/history-example",
        category="secret",
        severity=Severity.HIGH,
        file_path="deleted.py",
        line_start=1,
        message="A credential-like value was found in Git history.",
        redacted_evidence="[secret omitted]",
        confidence=Confidence.HIGH,
        remediation="Revoke the credential and remove it from history if appropriate.",
        engine="gitleaks",
    )


def test_history_cli_uses_canonical_report_and_exact_bounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = build_report(
        "repo",
        (),
        executions=(
            ScanExecution(
                engine="gitleaks-history",
                kind="secret",
                status="completed",
                version="8.30.1",
                elapsed_ms=20,
                checks=("git-history", "builtin-default"),
                revision_head="b" * 40,
                selected_commit_count=1,
            ),
        ),
    )
    calls: list[tuple[Path, str | None, str | None]] = []

    def fake_scan(root: Path, *, base_sha: str | None, head_sha: str | None) -> object:
        calls.append((root, base_sha, head_sha))
        return report

    monkeypatch.setattr(cli, "scan_history_path", fake_scan, raising=False)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        cli.app,
        [
            "scan-history",
            str(tmp_path),
            "--base",
            "a" * 40,
            "--head",
            "b" * 40,
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [(tmp_path.resolve(), "a" * 40, "b" * 40)]
    assert json.loads(output.read_text(encoding="utf-8"))["scan_id"] == str(report.scan_id)


@pytest.mark.parametrize(
    ("findings", "status"),
    [((_history_finding(),), "completed"), ((), "error")],
)
def test_history_cli_fails_on_findings_or_incomplete_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    findings: tuple[Finding, ...],
    status: str,
) -> None:
    report = build_report(
        "repo",
        findings,
        executions=(
            ScanExecution(
                engine="gitleaks-history",
                kind="secret",
                status=status,
                version="8.30.1",
                elapsed_ms=20,
                checks=("git-history", "builtin-default") if status == "completed" else (),
                revision_head="a" * 40 if status == "completed" else None,
                selected_commit_count=1 if status == "completed" else None,
            ),
        ),
    )
    monkeypatch.setattr(cli, "scan_history_path", lambda *_args, **_kwargs: report, raising=False)
    output = tmp_path / "history.sarif"

    result = CliRunner().invoke(
        cli.app,
        ["scan-history", str(tmp_path), "--format", "sarif", "-o", str(output)],
    )

    assert result.exit_code != 0
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_history_cli_hides_invalid_scan_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def invalid(*_args: object, **_kwargs: object) -> object:
        raise ValueError("fake-secret-should-not-escape")

    monkeypatch.setattr(cli, "scan_history_path", invalid, raising=False)
    result = CliRunner().invoke(cli.app, ["scan-history", str(tmp_path)])

    assert result.exit_code != 0
    assert "fake-secret-should-not-escape" not in result.output


def test_history_cli_rejects_unproven_completed_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = build_report(
        "repo",
        (),
        executions=(
            ScanExecution(
                engine="gitleaks-history", kind="secret", status="completed", elapsed_ms=1
            ),
        ),
    )
    monkeypatch.setattr(cli, "scan_history_path", lambda *_args, **_kwargs: report)

    result = CliRunner().invoke(cli.app, ["scan-history", str(tmp_path), "--format", "json"])

    assert result.exit_code != 0


def test_history_application_passes_one_redacted_result_through_graph(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import security_review.history as history
    from security_review.history_review import scan_history_path

    commit = "a" * 40
    finding = Finding.model_validate({**_history_finding().model_dump(), "git_commit": commit})
    execution = ScanExecution(
        engine="gitleaks-history",
        kind="secret",
        status="completed",
        elapsed_ms=20,
        revision_head=commit,
        selected_commit_count=1,
    )
    calls: list[tuple[Path, str | None, str | None, str]] = []

    def fake_scan(
        root: Path, *, base_sha: str | None, head_sha: str | None, binary: str
    ) -> SimpleNamespace:
        calls.append((root, base_sha, head_sha, binary))
        return SimpleNamespace(findings=(finding,), execution=execution, warnings=())

    monkeypatch.setattr(history, "scan_git_history", fake_scan)
    report = scan_history_path(tmp_path, head_sha=commit)

    assert calls == [(tmp_path, None, commit, "gitleaks")]
    assert report.findings[0].git_commit == commit
    assert report.executions == (execution,)
