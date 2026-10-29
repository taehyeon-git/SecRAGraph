"""Fail-closed tests for trusted, bounded Git history secret scanning."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from security_review.history import scan_git_history


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [shutil.which("git") or "git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str, str, str]:
    root = tmp_path / "trusted"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "History Test")
    _git(root, "config", "user.email", "history@example.invalid")
    (root / "README.md").write_text("safe\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-qm", "initial")
    base = _git(root, "rev-parse", "HEAD")
    fake_secret = "github_pat_" + secrets.token_urlsafe(64).replace("-", "A").replace("_", "B")
    (root / "deleted.txt").write_text(f"token={fake_secret}\n", encoding="utf-8")
    _git(root, "add", "deleted.txt")
    _git(root, "commit", "-qm", "add secret")
    secret_commit = _git(root, "rev-parse", "HEAD")
    (root / "deleted.txt").unlink()
    _git(root, "add", "-u")
    _git(root, "commit", "-qm", "delete secret")
    return root, base, secret_commit, fake_secret


def _metadata(
    commit: str, *, path: str = "deleted.txt", rule: str = "github-pat"
) -> dict[str, object]:
    return {
        "RuleID": rule,
        "File": path,
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 7,
        "EndColumn": 88,
        "Commit": commit,
    }


def _fake_gitleaks(
    monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, object]], *, exit_code: int = 0
) -> list[list[str]]:
    import security_review.history.engine as engine

    calls: list[list[str]] = []
    original_which = shutil.which
    monkeypatch.setattr(
        engine.shutil,
        "which",
        lambda name: "gitleaks-test" if name == "gitleaks" else original_which(name),
    )
    monkeypatch.setattr(engine, "_probe_version", lambda *args, **kwargs: "8.30.1")

    def invoke(command: list[str], **kwargs: object) -> int:
        calls.append(command)
        report = Path(command[command.index("--report-path") + 1])
        report.write_text(json.dumps(rows), encoding="utf-8")
        return exit_code

    monkeypatch.setattr(engine, "_invoke_gitleaks", invoke)
    return calls


def test_historical_deleted_file_has_commit_provenance_and_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, base, secret_commit, fake_secret = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [_metadata(secret_commit)])

    result = scan_git_history(root, base_sha=base, head_sha=_git(root, "rev-parse", "HEAD"))

    assert result.execution.status == "completed", result.execution.reason
    assert result.execution.revision_base == base
    assert result.execution.selected_commit_count == 2
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.git_commit == secret_commit
    assert finding.file_path == "deleted.txt"
    assert finding.category == "secret"
    assert fake_secret not in repr(result)
    log_options = calls[0][calls[0].index("--log-opts") + 1]
    assert log_options.startswith("--full-history -m --no-ext-diff --no-textconv --no-renames ")
    assert log_options.endswith(base + ".." + _git(root, "rev-parse", "HEAD"))
    assert "--ignore-gitleaks-allow" in calls[0]
    assert "--exit-code" in calls[0]


def test_clean_full_history_reports_complete_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [])

    result = scan_git_history(root)

    assert result.findings == ()
    assert result.execution.status == "completed"
    assert result.execution.revision_base is None
    assert result.execution.revision_head == _git(root, "rev-parse", "HEAD")
    assert result.execution.selected_commit_count == 3


@pytest.mark.parametrize("bad_ref", ["HEAD~1", "--all", "a" * 39, "z" * 40, "0" * 40])
def test_invalid_or_missing_refs_fail_before_gitleaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_ref: str
) -> None:
    root, _, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])

    result = scan_git_history(root, head_sha=bad_ref)

    assert result.execution.status != "completed"
    assert result.findings == ()
    assert not calls


def test_nonancestor_or_empty_range_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, base, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])
    head = _git(root, "rev-parse", "HEAD")

    for old, new in [(head, base), (head, head)]:
        result = scan_git_history(root, base_sha=old, head_sha=new)
        assert result.execution.status != "completed"
        assert result.findings == ()
    assert not calls


def test_unsafe_root_and_repo_ignore_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])
    assert scan_git_history(root.parent).execution.status != "completed"
    (root / ".gitleaksignore").write_text(".*\n", encoding="utf-8")
    result = scan_git_history(root)
    assert result.execution.status != "completed"
    assert not calls


@pytest.mark.parametrize("bad_path", ["../escape.txt", "C:/escape.txt", "/etc/passwd", "a\x00b"])
def test_report_path_must_be_safe_and_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_path: str
) -> None:
    root, _, secret_commit, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [_metadata(secret_commit, path=bad_path)])

    result = scan_git_history(root)

    assert result.execution.status != "completed"
    assert result.findings == ()


def test_unknown_commit_or_unexpected_report_field_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, secret_commit, _ = _repo(tmp_path)
    rows = [_metadata("f" * 40)]
    _fake_gitleaks(monkeypatch, rows)
    assert scan_git_history(root).execution.status != "completed"
    rows[:] = [{**_metadata(secret_commit), "Secret": "must-not-pass"}]
    assert scan_git_history(root).execution.status != "completed"


def test_nonzero_gitleaks_exit_never_reports_clean_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [], exit_code=1)

    result = scan_git_history(root)

    assert result.execution.status != "completed"
    assert result.findings == ()


def test_duplicate_parent_diffs_are_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, secret_commit, _ = _repo(tmp_path)
    row = _metadata(secret_commit)
    _fake_gitleaks(monkeypatch, [row, row])

    result = scan_git_history(root)

    assert result.execution.status == "completed"
    assert len(result.findings) == 1


def test_root_commit_can_be_selected_without_a_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, base, _, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [_metadata(base, path="README.md")])

    result = scan_git_history(root)

    assert result.execution.status == "completed"
    assert result.execution.selected_commit_count == 3
    assert result.findings[0].git_commit == base


def test_omitted_and_empty_base_are_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])

    result = scan_git_history(root, base_sha="")

    assert result.execution.status != "completed"
    assert not calls


def test_missing_or_malformed_report_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_review.history.engine as engine

    root, _, _, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [])
    monkeypatch.setattr(engine, "_invoke_gitleaks", lambda command, **kwargs: 0)
    missing = scan_git_history(root)
    assert missing.execution.status != "completed"
    assert missing.execution.reason == "missing_report"
    assert missing.findings == ()

    def malformed(command: list[str], **kwargs: object) -> int:
        Path(command[command.index("--report-path") + 1]).write_text("{", encoding="utf-8")
        return 0

    monkeypatch.setattr(engine, "_invoke_gitleaks", malformed)
    bad = scan_git_history(root)
    assert bad.execution.reason == "malformed_report"
    assert bad.findings == ()


def test_wrong_version_fails_before_gitleaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_review.history.engine as engine

    root, _, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])
    monkeypatch.setattr(engine, "_probe_version", lambda *args, **kwargs: "8.30.0")

    result = scan_git_history(root)

    assert result.execution.status != "completed"
    assert result.execution.reason == "scanner_version_mismatch"
    assert not calls


def test_selected_commit_cap_fails_before_gitleaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_review.history.engine as engine

    root, _, _, _ = _repo(tmp_path)
    calls = _fake_gitleaks(monkeypatch, [])
    monkeypatch.setattr(engine, "MAX_COMMITS", 2)

    result = scan_git_history(root)

    assert result.execution.reason == "history_limit_exceeded"
    assert not calls


def test_report_finding_cap_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import security_review.history.engine as engine

    root, _, secret_commit, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [_metadata(secret_commit), _metadata(secret_commit)])
    monkeypatch.setattr(engine, "MAX_FINDINGS", 1)

    result = scan_git_history(root)

    assert result.execution.reason == "finding_limit_exceeded"
    assert result.findings == ()


def test_safe_environment_disables_git_overrides(tmp_path: Path) -> None:
    from security_review.history.engine import _safe_env

    env = _safe_env(tmp_path)

    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_OPTIONAL_LOCKS"] == "0"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_GLOBAL"]
    assert env["GIT_CONFIG_SYSTEM"]
    assert "GIT_EXTERNAL_DIFF" not in env


def test_shallow_checkout_is_rejected_before_gitleaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, _ = _repo(tmp_path)
    (root / ".git" / "shallow").write_text(_git(root, "rev-parse", "HEAD") + "\n")
    assert _git(root, "rev-parse", "--is-shallow-repository") == "true"
    calls = _fake_gitleaks(monkeypatch, [])

    result = scan_git_history(root)

    assert result.execution.reason == "shallow_history"
    assert result.findings == ()
    assert not calls


def test_subprocess_timeout_is_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import security_review.history.engine as engine

    root, _, _, _ = _repo(tmp_path)
    actual_invoke = engine._invoke_gitleaks
    _fake_gitleaks(monkeypatch, [])
    expected = "history_timeout|scanner_cleanup_failed" if os.name == "nt" else "history_timeout"
    with pytest.raises(engine._HistoryError, match=expected):
        actual_invoke(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            cwd=tmp_path,
            env=engine._safe_env(tmp_path),
            timeout=0.01,
            report=tmp_path / "report.json",
        )

    def timeout(command: list[str], **kwargs: object) -> int:
        raise engine._HistoryError("history_timeout")

    monkeypatch.setattr(engine, "_invoke_gitleaks", timeout)
    result = scan_git_history(root)
    assert result.execution.reason == "history_timeout"
    assert result.findings == ()


def test_report_byte_cap_is_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import security_review.history.engine as engine

    root, _, secret_commit, _ = _repo(tmp_path)
    _fake_gitleaks(monkeypatch, [_metadata(secret_commit)])
    monkeypatch.setattr(engine, "MAX_REPORT_BYTES", 32)

    result = scan_git_history(root)

    assert result.execution.reason == "report_limit_exceeded"
    assert result.findings == ()


def test_growing_report_is_stopped_before_writer_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_review.history.engine as engine

    report = tmp_path / "report.json"
    monkeypatch.setattr(engine, "MAX_REPORT_BYTES", 32_768)
    script = (
        "from pathlib import Path; import sys,time; "
        "Path(sys.argv[1]).write_bytes(b'x' * 65536); time.sleep(5)"
    )
    from time import monotonic

    started = monotonic()
    expected = (
        "report_limit_exceeded|scanner_cleanup_failed"
        if os.name == "nt"
        else "report_limit_exceeded"
    )
    with pytest.raises(engine._HistoryError, match=expected):
        engine._invoke_gitleaks(
            [sys.executable, "-c", script, str(report)],
            cwd=tmp_path,
            env=engine._safe_env(tmp_path),
            timeout=3,
            report=report,
        )
    assert monotonic() - started < 2


@pytest.mark.skipif(os.name == "nt", reason="taskkill requires unsandboxed process permission")
def test_report_limit_terminates_scanner_child_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import security_review.history.engine as engine

    report = tmp_path / "report.json"
    marker = tmp_path / "orphan-marker"
    child = tmp_path / "child.py"
    child.write_text(
        "import sys,time\nfrom pathlib import Path\n"
        "time.sleep(1)\nPath(sys.argv[1]).write_text('orphan')\n",
        encoding="utf-8",
    )
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess,sys,time\nfrom pathlib import Path\n"
        "subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])\n"
        "Path(sys.argv[3]).write_bytes(b'x' * 65536)\n"
        "time.sleep(5)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(engine, "MAX_REPORT_BYTES", 32_768)

    with pytest.raises(engine._HistoryError, match="report_limit_exceeded"):
        engine._invoke_gitleaks(
            [sys.executable, str(parent), str(child), str(marker), str(report)],
            cwd=tmp_path,
            env=engine._safe_env(tmp_path),
            timeout=3,
            report=report,
        )
    time.sleep(1.3)
    assert not marker.exists()
