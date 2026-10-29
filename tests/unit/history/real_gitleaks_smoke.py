"""Run a real pinned Gitleaks history scan when Git and Gitleaks are available.

Usage: PYTHONPATH=src python tests/unit/history/real_gitleaks_smoke.py /path/to/gitleaks
This is an opt-in integration probe, so ordinary unit runs need no binary.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from security_review.history import scan_git_history


def _git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(  # noqa: S603  # nosec B603
        ["git", "-C", str(root), *args],  # noqa: S607  # nosec B607
        capture_output=True,
        text=True,
        timeout=20,
        check=check,
    )
    return result.stdout.strip()


def main(binary: str) -> None:
    with tempfile.TemporaryDirectory(prefix="secragraph-real-history-") as temporary:
        root = Path(temporary) / "repo"
        root.mkdir()
        _git(root, "init", "-q", "-b", "main")
        _git(root, "config", "user.name", "History Smoke")
        _git(root, "config", "user.email", "history@example.invalid")
        (root / "note.txt").write_text("safe\n", encoding="utf-8")
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "root")
        clean = scan_git_history(root, binary=binary)
        assert clean.execution.status == "completed", clean.execution.reason
        assert clean.execution.selected_commit_count == 1
        assert clean.findings == (), "clean root commit must yield an empty template report"

        first_key = "github_pat_" + secrets.token_hex(41)
        (root / "deleted.txt").write_text(f"token={first_key}\n", encoding="utf-8")
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "add credential")
        add_commit = _git(root, "rev-parse", "HEAD")
        (root / "deleted.txt").unlink()
        _git(root, "add", "-u")
        _git(root, "commit", "-qm", "remove credential")

        _git(root, "branch", "feature")
        (root / "note.txt").write_text("safe\nmain change\n", encoding="utf-8")
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "main change")
        _git(root, "checkout", "-q", "feature")
        (root / "note.txt").write_text("safe\nfeature change\n", encoding="utf-8")
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "feature change")
        _git(root, "checkout", "-q", "main")
        _git(root, "merge", "--no-ff", "feature", "-m", "conflicting merge", check=False)
        second_key = "github_pat_" + secrets.token_hex(41)
        (root / "note.txt").write_text(
            f"safe\nmain change\nfeature change\ntoken={second_key}\n", encoding="utf-8"
        )
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "merge credential only")
        merge_commit = _git(root, "rev-parse", "HEAD")
        (root / "note.txt").write_text("safe\nmain change\nfeature change\n", encoding="utf-8")
        _git(root, "add", ".")
        _git(root, "commit", "-qm", "remove merge credential")

        result = scan_git_history(root, binary=binary)
        assert result.execution.status == "completed", result.execution.reason
        detected = {finding.git_commit for finding in result.findings}
        assert add_commit in detected, "deleted-file secret missed"
        assert merge_commit in detected, "merge-resolution-only secret missed"
        assert all(finding.file_path in {"deleted.txt", "note.txt"} for finding in result.findings)
        assert first_key not in repr(result)
        assert second_key not in repr(result)
        print(
            "real_gitleaks_smoke: completed; "
            f"selected_commits={result.execution.selected_commit_count}; "
            f"findings={len(result.findings)}; "
            "clean_root_completed=true; deleted_and_merge_commits_detected=true"
        )


def baseline_from_bundle(binary: str, bundle: Path, head: str) -> None:
    """Check the full history of one exact commit without exposing finding paths."""
    with tempfile.TemporaryDirectory(prefix="secragraph-main-baseline-") as temporary:
        root = Path(temporary) / "repo"
        root.mkdir()
        _git(root, "init", "-q", "-b", "main")
        listed = _git(root, "bundle", "list-heads", str(bundle)).splitlines()
        matching = [line.split(" ", 1)[1] for line in listed if line.startswith(head + " ")]
        assert len(matching) == 1, "baseline commit missing or ambiguous in bundle"
        _git(root, "fetch", "-q", str(bundle), matching[0])
        _git(root, "checkout", "-q", "-b", "baseline", "FETCH_HEAD")
        result = scan_git_history(root, head_sha=head, binary=binary)
        print(
            "main_history_baseline: "
            f"status={result.execution.status}; "
            f"head={result.execution.revision_head}; "
            f"selected_commits={result.execution.selected_commit_count}; "
            f"findings={len(result.findings)}; "
            f"reason={result.execution.reason or 'none'}"
        )
        assert result.execution.status == "completed", result.execution.reason


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    elif len(sys.argv) == 5 and sys.argv[1] == "--bundle":
        baseline_from_bundle(sys.argv[4], Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit(
            "usage: real_gitleaks_smoke.py GITLEAKS_BINARY | "
            "--bundle BUNDLE HEAD_SHA GITLEAKS_BINARY"
        )
