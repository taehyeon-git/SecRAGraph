"""Select exact CI commits and emit redacted Git-history evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from security_review.domain.models import ScanReport, ScanStatus
from security_review.reporting.types import ReportFormat, render_report

_FULL_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_ARTIFACTS = ("history.json", "history.md", "history.sarif")
_MARKER = "history.validated.json"
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_EXPECTED_MESSAGE = "Potential exposed credential in Git history."
_EXPECTED_EVIDENCE = "[REDACTED: secret value omitted]"
_DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "build" / "evidence"
RESCAN_BASE_SHA = "313a2adc3968a37a1ce63d41a3d7531468a93d00"


@dataclass(frozen=True)
class HistorySelection:
    base_sha: str | None
    head_sha: str


def _git_output(root: Path, *arguments: str) -> str:
    """Run one bounded Git read without inherited Git override configuration."""

    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
        }
    )
    git = shutil.which("git")
    if git is None:
        raise ValueError("history_git_unavailable")
    try:
        process = subprocess.run(  # noqa: S603  # nosec B603
            [git, "--no-pager", "-C", str(root), *arguments],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("history_git_unavailable") from error
    if process.returncode != 0 or len(process.stdout) > 4096:
        raise ValueError("history_git_preflight_failed")
    return process.stdout.strip()


def _full_sha(value: str | None) -> str:
    if not isinstance(value, str) or _FULL_SHA.fullmatch(value) is None:
        raise ValueError("history_event_sha_invalid")
    return value.lower()


def _require_commit(root: Path, sha: str) -> None:
    if _git_output(root, "cat-file", "-t", sha) != "commit":
        raise ValueError("history_event_commit_unavailable")


def select_event_history(root: Path, event: Mapping[str, str]) -> HistorySelection:
    """Pin PR, push and trusted main re-scan bounds to real commits."""

    event_name = event.get("GITHUB_EVENT_NAME")
    if event_name == "pull_request":
        base = _full_sha(event.get("PR_BASE_SHA"))
        head = _full_sha(event.get("PR_HEAD_SHA"))
        _require_commit(root, base)
        _require_commit(root, head)
        merge_bases = _git_output(root, "merge-base", "--all", base, head).splitlines()
        if len(merge_bases) != 1:
            raise ValueError("history_event_merge_base_ambiguous")
        selected_base = _full_sha(merge_bases[0])
        if selected_base == head:
            raise ValueError("history_event_range_empty")
        return HistorySelection(selected_base, head)
    if event_name == "push":
        head = _full_sha(event.get("PUSH_AFTER_SHA"))
        if _full_sha(event.get("GITHUB_SHA")) != head:
            raise ValueError("history_event_head_mismatch")
        before = _full_sha(event.get("PUSH_BEFORE_SHA"))
        _require_commit(root, head)
        if before == "0" * len(head):
            return HistorySelection(None, head)
        _require_commit(root, before)
        if before == head:
            raise ValueError("history_event_range_empty")
        _git_output(root, "merge-base", "--is-ancestor", before, head)
        return HistorySelection(before, head)
    if event_name in {"schedule", "workflow_dispatch"}:
        if event.get("GITHUB_REF") != "refs/heads/main":
            raise ValueError("history_event_ref_untrusted")
        head = _full_sha(event.get("GITHUB_SHA"))
        checkout_head = _full_sha(_git_output(root, "rev-parse", "HEAD"))
        if head != checkout_head:
            raise ValueError("history_event_head_mismatch")
        base = _full_sha(RESCAN_BASE_SHA)
        _require_commit(root, base)
        _require_commit(root, head)
        if base == head:
            raise ValueError("history_event_range_empty")
        _git_output(root, "merge-base", "--is-ancestor", base, head)
        return HistorySelection(base, head)
    raise ValueError("history_event_unsupported")


def _scan(root: Path, base: str | None, head: str, binary: str) -> ScanReport:
    from security_review.history_review import scan_history_path

    return scan_history_path(root, base_sha=base, head_sha=head, binary=binary)


def _require_complete(report: ScanReport, selected: HistorySelection) -> None:
    if report.status is not ScanStatus.COMPLETED or report.warnings:
        raise ValueError("history_scan_incomplete")
    if len(report.executions) != 1:
        raise ValueError("history_execution_count_invalid")
    execution = report.executions[0]
    if (
        execution.engine != "gitleaks-history"
        or execution.kind != "secret"
        or execution.status != "completed"
        or execution.version != "8.30.1"
        or execution.revision_base != selected.base_sha
        or execution.revision_head != selected.head_sha
        or execution.selected_commit_count is None
        or execution.selected_commit_count < 1
        or execution.checks != ("git-history", "builtin-default")
    ):
        raise ValueError("history_execution_incomplete")
    for finding in report.findings:
        if (
            finding.engine != "gitleaks-history"
            or finding.category != "secret"
            or finding.file_path is None
            or finding.line_start is None
            or finding.git_commit is None
            or finding.trace
            or finding.message != _EXPECTED_MESSAGE
            or finding.redacted_evidence != _EXPECTED_EVIDENCE
            or finding.references
            or not finding.rule_id.startswith("GITLEAKS/")
        ):
            raise ValueError("history_finding_untrusted")


def _render_and_validate(report: ScanReport) -> dict[str, bytes]:
    rendered = {
        "history.json": render_report(report, ReportFormat.JSON),
        "history.md": render_report(report, ReportFormat.MARKDOWN),
        "history.sarif": render_report(report, ReportFormat.SARIF),
    }
    encoded = {name: content.encode("utf-8") for name, content in rendered.items()}
    if any(not value or len(value) > _MAX_ARTIFACT_BYTES for value in encoded.values()):
        raise ValueError("history_artifact_size_invalid")
    try:
        normalized = ScanReport.model_validate_json(encoded["history.json"])
        sarif = json.loads(encoded["history.sarif"])
        results = sarif["runs"][0]["results"]
        if not isinstance(results, list):
            raise TypeError
        if len(results) != len(report.findings):
            raise ValueError
        for result in results:
            locations = result["locations"]
            if not isinstance(locations, list) or len(locations) != 1:
                raise ValueError
            if "physicalLocation" in locations[0] or "logicalLocations" not in locations[0]:
                raise ValueError
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise ValueError("history_artifact_invalid") from error
    if normalized != report:
        raise ValueError("history_artifact_report_mismatch")
    return encoded


def _write_atomic(path: Path, content: bytes) -> None:
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="wb", prefix=".history-", dir=path.parent, delete=False
        ) as file:
            file.write(content)
            temporary = Path(file.name)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate_evidence(root: Path, event: Mapping[str, str], output_dir: Path, binary: str) -> None:
    """Render one completed CI scan; publish no validation marker on failure."""

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / _MARKER).unlink(missing_ok=True)
    selected = select_event_history(root, event)
    report = _scan(root, selected.base_sha, selected.head_sha, binary)
    _require_complete(report, selected)
    rendered = _render_and_validate(report)
    for name in _ARTIFACTS:
        _write_atomic(output_dir / name, rendered[name])
    marker = {
        "schema_version": 1,
        "finding_count": len(report.findings),
        "revision_base": selected.base_sha,
        "revision_head": selected.head_sha,
        "selected_commit_count": report.executions[0].selected_commit_count,
        "sha256": {name: hashlib.sha256(rendered[name]).hexdigest() for name in _ARTIFACTS},
    }
    _write_atomic(output_dir / _MARKER, json.dumps(marker, sort_keys=True).encode("utf-8"))


def gate_evidence(output_dir: Path) -> int:
    """Fail on findings after rechecking the validated artifact set."""

    marker_path = output_dir / _MARKER
    if not marker_path.is_file() or marker_path.stat().st_size > 4096:
        raise ValueError("history_validation_missing")
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if marker["schema_version"] != 1 or not isinstance(marker["finding_count"], int):
            raise ValueError
        if marker["finding_count"] < 0:
            raise ValueError
        if _full_sha(marker["revision_head"]) != marker["revision_head"]:
            raise ValueError
        if marker["revision_base"] is not None and (
            _full_sha(marker["revision_base"]) != marker["revision_base"]
        ):
            raise ValueError
        if not isinstance(marker["selected_commit_count"], int) or (
            marker["selected_commit_count"] < 1
        ):
            raise ValueError
        if set(marker["sha256"]) != set(_ARTIFACTS):
            raise ValueError
        for name in _ARTIFACTS:
            path = output_dir / name
            if not path.is_file() or not 0 < path.stat().st_size <= _MAX_ARTIFACT_BYTES:
                raise ValueError
            if hashlib.sha256(path.read_bytes()).hexdigest() != marker["sha256"][name]:
                raise ValueError
        report = ScanReport.model_validate_json((output_dir / "history.json").read_bytes())
        _require_complete(
            report,
            HistorySelection(marker["revision_base"], marker["revision_head"]),
        )
        if report.executions[0].selected_commit_count != marker["selected_commit_count"]:
            raise ValueError
        if len(report.findings) != marker["finding_count"]:
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise ValueError("history_validation_invalid") from error
    return 1 if marker["finding_count"] else 0


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify CI Git-history secret evidence")
    parser.add_argument("action", choices=("generate", "gate"))
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT)
    parser.add_argument("--binary", default="gitleaks")
    args = parser.parse_args(arguments)
    try:
        if args.action == "generate":
            generate_evidence(Path.cwd(), os.environ, args.output_dir, args.binary)
            print("history_evidence_validated")
            return 0
        result = gate_evidence(args.output_dir)
    except Exception:
        print("history_evidence_unavailable", file=sys.stderr)
        return 2
    print("history_findings_present" if result else "history_clean")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
