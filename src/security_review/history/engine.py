"""Bounded Gitleaks Git mode for a trusted local checkout only.

This entry point is intentionally separate from uploaded snapshot scanning. It
never checks out or runs code from a historical commit, and it never retains
Gitleaks' normal secret-bearing output.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic, sleep
from typing import Literal

from security_review.domain.models import Confidence, Finding, ScanExecution, Severity

GITLEAKS_VERSION = "8.30.1"
MAX_SECONDS = 300.0
MAX_COMMITS = 10_000
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 2_000
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_RULE = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
_VERSION = re.compile(r"\bv?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?)\b")
_REPORT_KEYS = frozenset(
    {"RuleID", "File", "StartLine", "EndLine", "StartColumn", "EndColumn", "Commit"}
)
_TEMPLATE = (
    "[{{range $i, $f := .}}{{if $i}},{{end}}"
    '{"RuleID":{{mustToJson $f.RuleID}},"File":{{mustToJson $f.File}},'
    '"StartLine":{{$f.StartLine}},"EndLine":{{$f.EndLine}},'
    '"StartColumn":{{$f.StartColumn}},"EndColumn":{{$f.EndColumn}},'
    '"Commit":{{mustToJson $f.Commit}}}{{end}}]'
)
_GIT_FLAGS = "--full-history -m --no-ext-diff --no-textconv --no-renames"


@dataclass(frozen=True, slots=True)
class HistoryScanResult:
    """Only redacted findings and proven execution metadata leave this module."""

    findings: tuple[Finding, ...]
    execution: ScanExecution
    warnings: tuple[str, ...]


class _HistoryError(ValueError):
    """Safe reason code; never includes Git or detector output."""


def _elapsed_ms(started: float) -> int:
    return max(0, int((monotonic() - started) * 1000))


def _result(
    started: float,
    *,
    status: Literal["completed", "error"],
    reason: str | None = None,
    findings: tuple[Finding, ...] = (),
    version: str | None = None,
    base: str | None = None,
    head: str | None = None,
    selected_count: int | None = None,
) -> HistoryScanResult:
    # A failed invocation cannot claim completed history coverage or findings.
    if status != "completed":
        findings = ()
        base = head = None
        selected_count = None
    execution = ScanExecution(
        engine="gitleaks-history",
        kind="secret",
        status=status,
        version=version,
        elapsed_ms=_elapsed_ms(started),
        checks=("git-history", "builtin-default") if status == "completed" else (),
        reason=reason,
        revision_base=base,
        revision_head=head,
        selected_commit_count=selected_count,
    )
    return HistoryScanResult(findings, execution, (reason,) if reason else ())


def _safe_env(work_dir: Path) -> dict[str, str]:
    """Drop caller Git overrides, credentials, hooks, trace and proxy settings."""
    retained = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC")
    env = {key: os.environ[key] for key in retained if key in os.environ}
    env.update(
        {
            "HOME": str(work_dir),
            "USERPROFILE": str(work_dir),
            "XDG_CONFIG_HOME": str(work_dir),
            "XDG_CACHE_HOME": str(work_dir),
            "TMP": str(work_dir),
            "TEMP": str(work_dir),
            "TMPDIR": str(work_dir),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.longpaths",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
    )
    return env


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _HistoryError("history_timeout")
    return remaining


def _git(
    binary: str, root: Path, args: list[str], *, env: dict[str, str], deadline: float
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(  # noqa: S603  # nosec B603
            [binary, "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=env["HOME"],
            env=env,
            timeout=min(15.0, _remaining(deadline)),
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise _HistoryError("history_timeout") from error
    except OSError as error:
        raise _HistoryError("git_unavailable") from error


def _git_value(
    binary: str, root: Path, args: list[str], *, env: dict[str, str], deadline: float
) -> str:
    result = _git(binary, root, args, env=env, deadline=deadline)
    if result.returncode != 0 or len(result.stdout or b"") > 1024:
        raise _HistoryError("invalid_git_checkout")
    try:
        return (result.stdout or b"").decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise _HistoryError("invalid_git_checkout") from error


def _is_link_like(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return True
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _validate_root(root: Path, git: str, *, env: dict[str, str], deadline: float) -> None:
    if _is_link_like(root) or not root.is_dir() or root.parent == root:
        raise _HistoryError("invalid_git_checkout")
    top = _git_value(git, root, ["rev-parse", "--show-toplevel"], env=env, deadline=deadline)
    try:
        if Path(top).resolve(strict=True) != root.resolve(strict=True):
            raise _HistoryError("invalid_git_checkout")
    except OSError as error:
        raise _HistoryError("invalid_git_checkout") from error
    bare = _git_value(git, root, ["rev-parse", "--is-bare-repository"], env=env, deadline=deadline)
    if bare != "false":
        raise _HistoryError("invalid_git_checkout")
    shallow = _git_value(
        git, root, ["rev-parse", "--is-shallow-repository"], env=env, deadline=deadline
    )
    if shallow != "false":
        raise _HistoryError("shallow_history")
    if os.path.lexists(root / ".gitleaksignore"):
        raise _HistoryError("repo_ignore_disallowed")


def _commit(
    value: str | None,
    git: str,
    root: Path,
    *,
    env: dict[str, str],
    deadline: float,
) -> str:
    if value is not None and (not isinstance(value, str) or not _SHA.fullmatch(value)):
        raise _HistoryError("invalid_revision")
    ref = "HEAD" if value is None else value
    result = _git(
        git, root, ["rev-parse", "--verify", f"{ref}^{{commit}}"], env=env, deadline=deadline
    )
    if result.returncode != 0:
        raise _HistoryError("missing_revision")
    try:
        commit = (result.stdout or b"").decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise _HistoryError("missing_revision") from error
    if not _SHA.fullmatch(commit) or (value is not None and commit != value.lower()):
        raise _HistoryError("invalid_revision")
    return commit


def _selected_commits(
    git: str,
    root: Path,
    base: str | None,
    head: str,
    *,
    env: dict[str, str],
    deadline: float,
) -> frozenset[str]:
    if base is not None:
        ancestor = _git(
            git, root, ["merge-base", "--is-ancestor", base, head], env=env, deadline=deadline
        )
        if ancestor.returncode != 0:
            raise _HistoryError("nonancestor_range")
    spec = f"{base}..{head}" if base else head
    result = _git(
        git,
        root,
        ["rev-list", f"--max-count={MAX_COMMITS + 1}", "--full-history", spec],
        env=env,
        deadline=deadline,
    )
    if result.returncode != 0 or len(result.stdout or b"") > (MAX_COMMITS + 1) * 66:
        raise _HistoryError("history_selection_failed")
    try:
        commits = (result.stdout or b"").decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise _HistoryError("history_selection_failed") from error
    if not commits:
        raise _HistoryError("empty_history_range")
    if len(commits) > MAX_COMMITS:
        raise _HistoryError("history_limit_exceeded")
    if len(commits) != len(set(commits)) or any(not _SHA.fullmatch(item) for item in commits):
        raise _HistoryError("history_selection_failed")
    return frozenset(commits)


def _probe_version(binary: str, work_dir: Path, env: dict[str, str], timeout: float) -> str | None:
    version_path = work_dir / "version.txt"
    try:
        with version_path.open("wb") as target:
            completed = subprocess.run(  # noqa: S603  # nosec B603
                [binary, "version"],
                stdout=target,
                stderr=subprocess.DEVNULL,
                cwd=str(work_dir),
                env=env,
                timeout=min(5.0, timeout),
                check=False,
            )
        if completed.returncode != 0 or version_path.stat().st_size > 256:
            return None
        output = version_path.read_text(encoding="ascii", errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _VERSION.search(output)
    return match.group(1) if match else None


def _command(
    binary: str,
    root: Path,
    *,
    base: str | None,
    head: str,
    config: Path,
    ignore: Path,
    template: Path,
    report: Path,
    timeout: float,
) -> list[str]:
    spec = f"{base}..{head}" if base else head
    return [
        binary,
        "git",
        str(root),
        "--log-opts",
        f"{_GIT_FLAGS} {spec}",
        "--config",
        str(config),
        "--gitleaks-ignore-path",
        str(ignore),
        "--ignore-gitleaks-allow",
        "--redact=100",
        "--no-banner",
        "--log-level",
        "error",
        "--max-archive-depth",
        "0",
        "--max-decode-depth",
        "2",
        "--exit-code",
        "0",
        "--timeout",
        str(max(1, math.ceil(timeout))),
        "--report-format",
        "template",
        "--report-template",
        str(template),
        "--report-path",
        str(report),
    ]


def _invoke_gitleaks(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: float, report: Path
) -> int:
    try:
        process = subprocess.Popen(  # noqa: S603  # nosec B603
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(cwd),
            env=env,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
    except OSError as error:
        raise _HistoryError("scanner_failed") from error
    deadline = monotonic() + timeout
    completed = False
    try:
        while True:
            try:
                if report.stat().st_size > MAX_REPORT_BYTES:
                    raise _HistoryError("report_limit_exceeded")
            except FileNotFoundError:
                pass
            except OSError as error:
                raise _HistoryError("report_monitor_failed") from error
            exit_code = process.poll()
            if exit_code is not None:
                completed = True
                return exit_code
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise _HistoryError("history_timeout")
            sleep(min(0.05, remaining))
    finally:
        if not completed:
            _stop_process_tree(process)


def _stop_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Stop Gitleaks and the Git child that may still be writing a report."""
    try:
        if os.name == "nt":
            taskkill = shutil.which("taskkill")
            if taskkill is None:
                _kill_parent(process)
                raise _HistoryError("scanner_cleanup_failed")
            try:
                killed = subprocess.run(  # noqa: S603  # nosec B603
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                _kill_parent(process)
                raise _HistoryError("scanner_cleanup_failed") from error
            if killed.returncode != 0:
                _kill_parent(process)
                raise _HistoryError("scanner_cleanup_failed")
        else:
            try:
                os.kill(-process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.kill(-process.pid, 9)  # POSIX SIGKILL for the scanner process group.
                except ProcessLookupError:
                    pass
            process.wait(timeout=3)
        if os.name != "nt":
            # The parent can exit while a Git child survives SIGTERM.
            try:
                os.kill(-process.pid, 9)  # POSIX SIGKILL for any remaining Git child.
            except ProcessLookupError:
                pass
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _HistoryError("scanner_cleanup_failed") from error


def _kill_parent(process: subprocess.Popen[bytes]) -> None:
    """Best-effort Windows fallback when taskkill cannot confirm child cleanup."""
    if process.poll() is not None:
        return
    try:
        process.kill()
        process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _HistoryError("scanner_cleanup_failed") from error


def _read_report(path: Path) -> object:
    try:
        with path.open("rb") as source:
            payload = source.read(MAX_REPORT_BYTES + 1)
    except OSError as error:
        raise _HistoryError("missing_report") from error
    if len(payload) > MAX_REPORT_BYTES:
        raise _HistoryError("report_limit_exceeded")
    try:
        return json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _HistoryError("malformed_report") from error


def _historical_path(raw: object) -> str:
    if (
        not isinstance(raw, str)
        or not 1 <= len(raw) <= 1024
        or "\\" in raw
        or ":" in raw
        or raw.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
        or any(part in {"", ".", ".."} or len(part) > 255 for part in raw.split("/"))
    ):
        raise _HistoryError("unsafe_report_path")
    path = PurePosixPath(raw)
    if path.is_absolute() or path.as_posix() != raw:
        raise _HistoryError("unsafe_report_path")
    return raw


def _position(raw: object) -> int:
    if type(raw) is not int or not 1 <= raw <= 10_000_000:
        raise _HistoryError("invalid_report_location")
    return raw


def _parse_report(payload: object, selected: frozenset[str]) -> tuple[Finding, ...]:
    if not isinstance(payload, list):
        raise _HistoryError("malformed_report")
    if len(payload) > MAX_FINDINGS:
        raise _HistoryError("finding_limit_exceeded")
    unique: dict[str, Finding] = {}
    for item in payload:
        if not isinstance(item, dict) or item.keys() != _REPORT_KEYS:
            raise _HistoryError("malformed_report")
        rule = item["RuleID"]
        if not isinstance(rule, str) or not _RULE.fullmatch(rule):
            raise _HistoryError("invalid_report_rule")
        path = _historical_path(item["File"])
        start = _position(item["StartLine"])
        end = _position(item["EndLine"])
        start_column = _position(item["StartColumn"])
        end_column = _position(item["EndColumn"])
        if end < start or (end == start and end_column < start_column):
            raise _HistoryError("invalid_report_location")
        commit = item["Commit"]
        if not isinstance(commit, str) or commit not in selected:
            raise _HistoryError("unknown_report_commit")
        identity = json.dumps(
            ["gitleaks-history", commit, rule, path, start, start_column],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        finding_id = "GITLEAKS-HISTORY-" + sha256(identity.encode("ascii")).hexdigest()[:24]
        unique[finding_id] = Finding(
            id=finding_id,
            rule_id=f"GITLEAKS/{rule}",
            category="secret",
            severity=Severity.HIGH,
            file_path=path,
            line_start=start,
            line_end=end,
            git_commit=commit,
            message="Potential exposed credential in Git history.",
            redacted_evidence="[REDACTED: secret value omitted]",
            confidence=Confidence.MEDIUM,
            engine="gitleaks-history",
            remediation=(
                "Revoke the credential if valid and move its replacement to a secret store."
            ),
        )
    return tuple(unique[key] for key in sorted(unique))


def scan_git_history(
    root: Path,
    base_sha: str | None = None,
    head_sha: str | None = None,
    binary: str = "gitleaks",
) -> HistoryScanResult:
    """Scan a trusted checkout's selected Git commits with pinned Gitleaks.

    Returned errors are code-only. A caller must treat any non-completed status
    as a failed scan, even when no findings are present.
    """
    started = monotonic()
    deadline = started + MAX_SECONDS
    version: str | None = None
    try:
        root = Path(root).absolute()
        if not isinstance(binary, str) or not binary or "\x00" in binary:
            raise _HistoryError("tool_unavailable")
        git = shutil.which("git")
        scanner = shutil.which(binary)
        if git is None:
            raise _HistoryError("git_unavailable")
        if scanner is None:
            raise _HistoryError("tool_unavailable")
        # A sibling directory keeps configs and the metadata report outside the checkout.
        with tempfile.TemporaryDirectory(prefix="secragraph-history-", dir=root.parent) as temp:
            work_dir = Path(temp)
            env = _safe_env(work_dir)
            _validate_root(root, git, env=env, deadline=deadline)
            head = _commit(head_sha, git, root, env=env, deadline=deadline)
            base = (
                _commit(base_sha, git, root, env=env, deadline=deadline)
                if base_sha is not None
                else None
            )
            selected = _selected_commits(git, root, base, head, env=env, deadline=deadline)
            version = _probe_version(scanner, work_dir, env, _remaining(deadline))
            if version != GITLEAKS_VERSION:
                raise _HistoryError("scanner_version_mismatch")
            config = work_dir / "trusted.toml"
            config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            ignore = work_dir / ".gitleaksignore"
            ignore.write_text("", encoding="utf-8")
            template = work_dir / "safe-report.tmpl"
            template.write_text(_TEMPLATE, encoding="utf-8")
            report = work_dir / "report.json"
            remaining = _remaining(deadline)
            command = _command(
                scanner,
                root,
                base=base,
                head=head,
                config=config,
                ignore=ignore,
                template=template,
                report=report,
                timeout=remaining,
            )
            exit_code = _invoke_gitleaks(
                command, cwd=work_dir, env=env, timeout=remaining, report=report
            )
            if exit_code != 0:
                raise _HistoryError("scanner_failed")
            _remaining(deadline)
            findings = _parse_report(_read_report(report), selected)
            _remaining(deadline)
            return _result(
                started,
                status="completed",
                findings=findings,
                version=version,
                base=base,
                head=head,
                selected_count=len(selected),
            )
    except _HistoryError as error:
        return _result(started, status="error", reason=str(error), version=version)
    except (OSError, ValueError, TypeError):
        # Temp creation/cleanup and invalid caller paths must not produce clean coverage.
        return _result(started, status="error", reason="history_scan_failed", version=version)
