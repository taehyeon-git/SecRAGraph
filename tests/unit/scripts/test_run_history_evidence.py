"""CI history selection is based on immutable event commits, not checkout refs."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import run_history_evidence
from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.reporting.builder import build_report
from security_review.reporting.types import ReportFormat


def _git(root: Path, *args: str) -> str:
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603 - test fixture invokes fixed Git binary.
        [git, "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def test_git_preflight_fails_closed_without_git(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(run_history_evidence.shutil, "which", lambda _name: None)

    with pytest.raises(ValueError):
        run_history_evidence._git_output(tmp_path, "rev-parse", "HEAD")


def _commit(root: Path, name: str) -> str:
    (root / name).write_text(name, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "-q", "-m", name)
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path: Path) -> tuple[Path, str, str, str, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "config", "user.name", "History Test")
    _git(root, "config", "user.email", "history@example.invalid")
    ancestor = _commit(root, "ancestor.txt")
    _git(root, "switch", "-q", "-c", "feature")
    feature_head = _commit(root, "feature.txt")
    _git(root, "switch", "-q", "main")
    base_head = _commit(root, "main.txt")
    _git(root, "merge", "-q", "--no-ff", "feature", "-m", "synthetic-merge")
    merge = _git(root, "rev-parse", "HEAD")
    return root, ancestor, feature_head, base_head, merge


def test_pr_scans_actual_head_since_unique_merge_base(history) -> None:
    root, ancestor, feature_head, base_head, synthetic_merge = history

    selected = run_history_evidence.select_event_history(
        root,
        {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": synthetic_merge,
            "PR_HEAD_SHA": feature_head,
            "PR_BASE_SHA": base_head,
        },
    )

    assert selected.base_sha == ancestor
    assert selected.head_sha == feature_head
    assert selected.head_sha != synthetic_merge


def test_push_uses_before_after_and_initial_push_scans_full_history(history) -> None:
    root, ancestor, _, base_head, _ = history

    changed = run_history_evidence.select_event_history(
        root,
        {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": base_head,
            "PUSH_BEFORE_SHA": ancestor,
            "PUSH_AFTER_SHA": base_head,
        },
    )
    initial = run_history_evidence.select_event_history(
        root,
        {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": base_head,
            "PUSH_BEFORE_SHA": "0" * 40,
            "PUSH_AFTER_SHA": base_head,
        },
    )

    assert (changed.base_sha, changed.head_sha) == (ancestor, base_head)
    assert (initial.base_sha, initial.head_sha) == (None, base_head)


@pytest.mark.parametrize("before,after", [("feature", "main"), ("bad", "main")])
def test_push_rejects_nonancestor_and_malformed_sha(history, before: str, after: str) -> None:
    root, _, feature_head, base_head, _ = history
    values = {"feature": feature_head, "main": base_head, "bad": "--help"}

    with pytest.raises(ValueError):
        run_history_evidence.select_event_history(
            root,
            {
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_SHA": base_head,
                "PUSH_BEFORE_SHA": values[before],
                "PUSH_AFTER_SHA": values[after],
            },
        )


def test_pr_rejects_missing_head_object(history) -> None:
    root, _, _, base_head, synthetic_merge = history

    with pytest.raises(ValueError):
        run_history_evidence.select_event_history(
            root,
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_SHA": synthetic_merge,
                "PR_HEAD_SHA": "f" * 40,
                "PR_BASE_SHA": base_head,
            },
        )


def test_pr_rejects_multiple_merge_bases(history, monkeypatch) -> None:
    root, ancestor, feature_head, base_head, synthetic_merge = history
    real_git_output = run_history_evidence._git_output

    def duplicate_merge_base(path: Path, *arguments: str) -> str:
        if arguments[:2] == ("merge-base", "--all"):
            return f"{ancestor}\n{base_head}"
        return real_git_output(path, *arguments)

    monkeypatch.setattr(run_history_evidence, "_git_output", duplicate_merge_base)

    with pytest.raises(ValueError):
        run_history_evidence.select_event_history(
            root,
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_SHA": synthetic_merge,
                "PR_HEAD_SHA": feature_head,
                "PR_BASE_SHA": base_head,
            },
        )


_BASE = "a" * 40
_HEAD = "b" * 40


def _report(*, finding: bool = False, complete: bool = True, raw_evidence: bool = False):
    execution = ScanExecution(
        engine="gitleaks-history",
        kind="secret",
        status="completed" if complete else "partial",
        version="8.30.1",
        elapsed_ms=10,
        checks=("git-history", "builtin-default") if complete else (),
        revision_base=_BASE if complete else None,
        revision_head=_HEAD if complete else None,
        selected_commit_count=1 if complete else None,
        reason=None if complete else "history_timeout",
    )
    findings = (
        (
            Finding(
                id="history-finding-1",
                rule_id="GITLEAKS/generic-api-key",
                category="secret",
                severity=Severity.HIGH,
                file_path="old.txt",
                line_start=1,
                git_commit=_HEAD,
                message="Potential exposed credential in Git history.",
                redacted_evidence=(
                    "unsafe-raw-token" if raw_evidence else "[REDACTED: secret value omitted]"
                ),
                confidence=Confidence.HIGH,
                remediation="Revoke and rotate the exposed credential.",
                engine="gitleaks-history",
            ),
        )
        if finding
        else ()
    )
    return build_report("repo", findings, executions=(execution,))


@pytest.mark.parametrize("with_finding,expected_gate", [(False, 0), (True, 1)])
def test_evidence_generation_scans_once_and_gate_uses_verified_report(
    tmp_path: Path, monkeypatch, with_finding: bool, expected_gate: int
) -> None:
    selected = run_history_evidence.HistorySelection(_BASE, _HEAD)
    monkeypatch.setattr(run_history_evidence, "select_event_history", lambda *_: selected)
    calls: list[tuple[Path, str | None, str, str]] = []
    report = _report(finding=with_finding)

    def scan(root: Path, base: str | None, head: str, binary: str):
        calls.append((root, base, head, binary))
        return report

    monkeypatch.setattr(run_history_evidence, "_scan", scan)
    output = tmp_path / "evidence"

    run_history_evidence.generate_evidence(tmp_path, {}, output, "pinned-gitleaks")

    assert calls == [(tmp_path, _BASE, _HEAD, "pinned-gitleaks")]
    assert (output / "history.json").is_file()
    assert (output / "history.md").is_file()
    assert (output / "history.sarif").is_file()
    assert (output / "history.validated.json").is_file()
    assert run_history_evidence.gate_evidence(output) == expected_gate
    if with_finding:
        assert _HEAD in (output / "history.md").read_text(encoding="utf-8")


def test_incomplete_history_never_publishes_validation_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        run_history_evidence,
        "select_event_history",
        lambda *_: run_history_evidence.HistorySelection(_BASE, _HEAD),
    )
    monkeypatch.setattr(run_history_evidence, "_scan", lambda *_: _report(complete=False))
    output = tmp_path / "evidence"

    with pytest.raises(ValueError):
        run_history_evidence.generate_evidence(tmp_path, {}, output, "pinned-gitleaks")

    assert not (output / "history.validated.json").exists()


def test_raw_evidence_is_rejected_before_artifact_write(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        run_history_evidence,
        "select_event_history",
        lambda *_: run_history_evidence.HistorySelection(_BASE, _HEAD),
    )
    monkeypatch.setattr(
        run_history_evidence, "_scan", lambda *_: _report(finding=True, raw_evidence=True)
    )
    output = tmp_path / "evidence"

    with pytest.raises(ValueError):
        run_history_evidence.generate_evidence(tmp_path, {}, output, "pinned-gitleaks")

    assert not (output / "history.validated.json").exists()
    assert not (output / "history.json").exists()


def test_gate_rejects_modified_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        run_history_evidence,
        "select_event_history",
        lambda *_: run_history_evidence.HistorySelection(_BASE, _HEAD),
    )
    monkeypatch.setattr(run_history_evidence, "_scan", lambda *_: _report())
    output = tmp_path / "evidence"
    run_history_evidence.generate_evidence(tmp_path, {}, output, "pinned-gitleaks")
    (output / "history.md").write_text("changed", encoding="utf-8")

    with pytest.raises(ValueError):
        run_history_evidence.gate_evidence(output)


def test_history_sarif_rejects_current_file_location(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        run_history_evidence,
        "select_event_history",
        lambda *_: run_history_evidence.HistorySelection(_BASE, _HEAD),
    )
    monkeypatch.setattr(run_history_evidence, "_scan", lambda *_: _report(finding=True))
    real_render = run_history_evidence.render_report

    def render(report, format: ReportFormat) -> str:
        if format is ReportFormat.SARIF:
            return '{"runs":[{"results":[{"locations":[{"physicalLocation":{}}]}]}]}'
        return real_render(report, format)

    monkeypatch.setattr(run_history_evidence, "render_report", render)
    output = tmp_path / "evidence"

    with pytest.raises(ValueError):
        run_history_evidence.generate_evidence(tmp_path, {}, output, "pinned-gitleaks")

    assert not (output / "history.validated.json").exists()


def test_history_ci_job_uses_full_credential_free_checkout_and_exact_event_shas() -> None:
    root = Path(__file__).resolve().parents[3]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["git-history-secrets"]
    assert job["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] <= 15
    steps = job["steps"]
    checkout = next(step for step in steps if "actions/checkout@" in step.get("uses", ""))
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    generate = next(step for step in steps if step.get("id") == "history_generate")
    assert generate["env"] == {
        "PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "PUSH_BEFORE_SHA": "${{ github.event.before }}",
        "PUSH_AFTER_SHA": "${{ github.event.after }}",
    }
    assert "scripts.run_history_evidence generate" in generate["run"]
    assert all("pull_request_target" not in str(step) for step in steps)


def test_history_ci_gate_precedes_clean_main_only_upload() -> None:
    root = Path(__file__).resolve().parents[3]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["git-history-secrets"]["steps"]
    installer = next(i for i, step in enumerate(steps) if "--gitleaks-only" in step.get("run", ""))
    generate = next(i for i, step in enumerate(steps) if step.get("id") == "history_generate")
    gate = next(i for i, step in enumerate(steps) if step.get("id") == "history_gate")
    upload = next(
        i for i, step in enumerate(steps) if "actions/upload-artifact@" in step.get("uses", "")
    )
    assert installer < generate < gate < upload
    upload_step = steps[upload]
    condition = upload_step["if"]
    assert "github.event_name == 'push'" in condition
    assert "github.ref == 'refs/heads/main'" in condition
    assert "steps.history_generate.outcome == 'success'" in condition
    assert "steps.history_gate.outcome == 'success'" in condition
    assert set(upload_step["with"]["path"].splitlines()) == {
        "build/evidence/history.json",
        "build/evidence/history.md",
        "build/evidence/history.sarif",
    }
    assert upload_step["with"]["if-no-files-found"] == "error"


def test_history_ci_fetches_exact_fork_pr_head_before_scanning() -> None:
    root = Path(__file__).resolve().parents[3]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["git-history-secrets"]["steps"]
    fetch_index = next(i for i, step in enumerate(steps) if step.get("id") == "history_pr_head")
    generate_index = next(i for i, step in enumerate(steps) if step.get("id") == "history_generate")
    fetch = steps[fetch_index]

    assert fetch_index < generate_index
    assert fetch["if"] == "github.event_name == 'pull_request'"
    assert fetch["env"] == {
        "PR_NUMBER": "${{ github.event.pull_request.number }}",
        "PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    }
    assert "refs/pull/$PR_NUMBER/head:refs/remotes/origin/history-pr-head" in fetch["run"]
    assert 'test "$fetched_head" = "$PR_HEAD_SHA"' in fetch["run"]
    assert "*[!0-9]*" in fetch["run"]
