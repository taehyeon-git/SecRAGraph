from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_review.domain.models import (
    Confidence,
    Finding,
    ScanExecution,
    Severity,
    TraceLocation,
)

COMMIT = "a" * 40
BASE_COMMIT = "b" * 40
SHA256_COMMIT = "b" * 64


def _historical_finding(**changes: object) -> Finding:
    values: dict[str, object] = {
        "id": f"gitleaks:{COMMIT}:settings.py:2",
        "rule_id": "gitleaks:generic-api-key",
        "category": "secret",
        "severity": Severity.HIGH,
        "file_path": "settings.py",
        "line_start": 2,
        "message": "A secret-like value was found in Git history.",
        "redacted_evidence": "[REDACTED: secret value omitted]",
        "confidence": Confidence.HIGH,
        "remediation": "Rotate the credential.",
        "engine": "gitleaks",
        "git_commit": COMMIT,
    }
    values.update(changes)
    return Finding.model_validate(values)


@pytest.mark.parametrize("commit", [COMMIT, SHA256_COMMIT])
def test_historical_finding_accepts_full_lowercase_commit(commit: str) -> None:
    finding = _historical_finding(git_commit=commit)

    assert finding.git_commit == commit
    assert finding.model_dump(mode="json")["git_commit"] == commit


@pytest.mark.parametrize("commit", ["a" * 39, "a" * 41, "A" * 40, "a" * 40 + "\n", "z" * 40])
def test_historical_finding_rejects_invalid_commit(commit: str) -> None:
    with pytest.raises(ValidationError, match="git_commit"):
        _historical_finding(git_commit=commit)


def test_historical_finding_requires_source_line_and_no_unversioned_trace() -> None:
    with pytest.raises(ValidationError):
        _historical_finding(file_path=None, line_start=None, http_method="GET", http_path="/api")
    with pytest.raises(ValidationError, match="trace"):
        _historical_finding(
            trace=(TraceLocation(file_path="settings.py", line_start=2, role="sink"),)
        )


def _history_execution(**changes: object) -> ScanExecution:
    values: dict[str, object] = {
        "engine": "gitleaks",
        "kind": "secret",
        "status": "completed",
        "elapsed_ms": 19,
        "revision_head": COMMIT,
        "selected_commit_count": 2,
        "checks": ("git-history",),
    }
    values.update(changes)
    return ScanExecution.model_validate(values)


def test_history_execution_tracks_selected_revision_range_without_file_inventory() -> None:
    execution = _history_execution(revision_base=BASE_COMMIT)

    assert execution.revision_base == BASE_COMMIT
    assert execution.revision_head == COMMIT
    assert execution.selected_commit_count == 2
    assert execution.scanned_files == ()


@pytest.mark.parametrize(
    "changes",
    [
        {"revision_head": None},
        {"revision_head": None, "selected_commit_count": None, "revision_base": COMMIT},
        {"selected_commit_count": None},
        {"selected_commit_count": 0},
        {"revision_head": "a" * 8},
        {"revision_base": "A" * 40},
        {"revision_base": SHA256_COMMIT},
        {"kind": "sast"},
        {"eligible_files": ("settings.py",)},
        {"scanned_files": ("settings.py",)},
    ],
)
def test_history_execution_rejects_inconsistent_or_nonsecret_range(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _history_execution(**changes)


def test_regular_secret_execution_remains_valid_without_revision_fields() -> None:
    execution = ScanExecution(engine="gitleaks", kind="secret", status="completed", elapsed_ms=1)

    assert execution.revision_head is None
    assert execution.selected_commit_count is None
