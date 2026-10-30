"""Dedicated, source-free adapters for secret and IaC configuration scanning.

Only metadata selected by this module leaves a subprocess. The target is a
bounded snapshot built by the caller; it is never built, imported, or run.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import Any

from security_review.domain.models import Confidence, Finding, Severity
from security_review.scanner.compose_files import is_compose_file
from security_review.scanner.external_common import (
    ExternalExecution,
    ExternalScanResult,
    ExternalStatus,
)

_MAX_REPORT_BYTES = 32_000_000
_MAX_FINDINGS = 2_000
_MAX_CHECKOV_RECORDS = 20_000
_MAX_CHECKS = 1_000
_MAX_STAGED_FILES = 500
_MAX_STAGED_BYTES = 20_000_000
_RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,100}\Z")
_VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?\b")
_GITLEAKS_TEMPLATE = (
    "[{{range $i, $f := .}}{{if $i}},{{end}}"
    '{"RuleID":{{quote $f.RuleID}},"File":{{quote $f.File}},'
    '"StartLine":{{$f.StartLine}},"EndLine":{{$f.EndLine}},'
    '"StartColumn":{{$f.StartColumn}}}{{end}}]'
)


class _UnsafeSnapshot(ValueError):
    pass


class _InvalidReport(ValueError):
    pass


class _StagingTimeout(ValueError):
    pass


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _snapshot_files(root: Path) -> tuple[str, ...]:
    """Inspect file names only, rejecting links that could escape the snapshot."""

    if _is_link_like(root) or not root.is_dir():
        raise _UnsafeSnapshot("invalid_snapshot")
    found: list[str] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if _is_link_like(current_path / directory):
                raise _UnsafeSnapshot("snapshot_contains_link")
        for name in files:
            path = current_path / name
            if _is_link_like(path) or not path.is_file():
                raise _UnsafeSnapshot("snapshot_contains_link")
            found.append(path.relative_to(root).as_posix())
    return tuple(sorted(found))


def _safe_env(work_dir: Path) -> dict[str, str]:
    """Keep platform launch variables, discarding API keys and scanner overrides."""

    retained = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC")
    env = {name: os.environ[name] for name in retained if name in os.environ}
    env.update(
        {
            "HOME": str(work_dir),
            "USERPROFILE": str(work_dir),
            "APPDATA": str(work_dir),
            "LOCALAPPDATA": str(work_dir),
            "XDG_CONFIG_HOME": str(work_dir),
            "XDG_CACHE_HOME": str(work_dir),
            "TMP": str(work_dir),
            "TEMP": str(work_dir),
            "TMPDIR": str(work_dir),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LOG_LEVEL": "ERROR",
            "CKV_IGNORE_HIDDEN_DIRECTORIES": "false",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
    )
    return env


def _probe_version(binary: str, timeout: float, work_dir: Path) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [binary, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(timeout, 5.0),
            cwd=str(work_dir),
            env=_safe_env(work_dir),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout or b""
    match = _VERSION.search(output[:256].decode("utf-8", errors="replace"))
    return match.group() if match else None


def _read_report(path: Path) -> Any:
    try:
        with path.open("rb") as source:
            payload = source.read(_MAX_REPORT_BYTES + 1)
    except OSError as error:
        raise _InvalidReport("missing_report") from error
    if len(payload) > _MAX_REPORT_BYTES:
        raise _InvalidReport("report_too_large")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _InvalidReport("malformed_report") from error


def _relative_report_path(
    raw: object,
    root: Path,
    eligible: frozenset[str],
    *,
    root_relative_slash: bool = False,
) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise _InvalidReport("unsafe_report_path")
    if root_relative_slash and raw.startswith("/") and not raw.startswith("//"):
        raw = raw.lstrip("/")
    candidate_path = Path(raw)
    if candidate_path.is_absolute():
        try:
            normalized = candidate_path.resolve(strict=False).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise _InvalidReport("unsafe_report_path") from error
        relative = normalized.as_posix()
    else:
        normalized_raw = raw.replace("\\", "/")
        path = PurePosixPath(normalized_raw)
        if path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise _InvalidReport("unsafe_report_path")
        relative = path.as_posix()
    if relative not in eligible:
        raise _InvalidReport("unsafe_report_path")
    return relative


def _rule_id(raw: object) -> str:
    if not isinstance(raw, str) or _RULE_ID.fullmatch(raw) is None:
        raise _InvalidReport("invalid_rule_id")
    return raw


def _line(raw: object, *, default: int | None = None) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        if default is not None:
            return default
        raise _InvalidReport("invalid_line")
    return raw


def _finding_id(engine: str, *identity: object) -> str:
    encoded = "\0".join(str(part) for part in identity).encode("utf-8")
    return f"{engine.upper()}-{sha256(encoded).hexdigest()[:24]}"


def _result(
    scanner: str,
    started: float,
    *,
    version: str | None = None,
    status: ExternalStatus,
    eligible_files: tuple[str, ...] = (),
    inspected_files: tuple[str, ...] = (),
    skipped: tuple[tuple[str, str], ...] = (),
    checks: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
    findings: tuple[Finding, ...] = (),
) -> ExternalScanResult:
    return ExternalScanResult(
        findings=findings,
        execution=ExternalExecution(
            scanner=scanner,
            version=version,
            status=status,
            eligible_files=eligible_files,
            inspected_files=inspected_files,
            skipped=skipped,
            checks=checks,
            duration_ms=max(0, int((monotonic() - started) * 1000)),
            warnings=warnings,
        ),
    )


@dataclass(frozen=True, slots=True)
class GitleaksAdapter:
    """Scan with built-in rules; Gitleaks reports finding paths, not all inspected files."""

    binary: str = "gitleaks"

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        started = monotonic()
        try:
            files = _snapshot_files(root)
        except _UnsafeSnapshot as error:
            return _result("gitleaks", started, status="error", warnings=(str(error),))
        root = root.absolute()
        if not files:
            return _result("gitleaks", started, status="skipped", warnings=("no_eligible_files",))
        if timeout <= 0 or not math.isfinite(timeout):
            return _result(
                "gitleaks",
                started,
                status="error",
                eligible_files=files,
                warnings=("invalid_timeout",),
            )
        deadline = started + timeout
        binary = shutil.which(self.binary)
        if binary is None:
            return _result(
                "gitleaks",
                started,
                status="not_run",
                eligible_files=files,
                warnings=("tool_unavailable",),
            )
        # Gitleaks always loads root/.gitleaksignore even with a trusted ignore path.
        # A caller can omit this control file from its snapshot to get full coverage.
        target_ignore_present = ".gitleaksignore" in files
        with tempfile.TemporaryDirectory(
            prefix="secragraph-gitleaks-", dir=root.parent
        ) as temporary:
            work_dir = Path(temporary)
            config = work_dir / "trusted.toml"
            config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            template = work_dir / "safe-report.tmpl"
            template.write_text(_GITLEAKS_TEMPLATE, encoding="utf-8")
            ignore = work_dir / ".gitleaksignore"
            ignore.write_text("", encoding="utf-8")
            report = work_dir / "report.json"
            version = _probe_version(binary, max(0.0, deadline - monotonic()), work_dir)
            remaining = deadline - monotonic()
            if remaining <= 0:
                return _result(
                    "gitleaks",
                    started,
                    version=version,
                    status="partial",
                    eligible_files=files,
                    warnings=("scanner_timeout",),
                )
            command = [
                binary,
                "dir",
                str(root),
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
                str(max(1, math.ceil(remaining))),
                "--report-format",
                "template",
                "--report-template",
                str(template),
                "--report-path",
                str(report),
            ]
            try:
                completed = subprocess.run(  # noqa: S603  # nosec B603
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=remaining,
                    cwd=str(work_dir),
                    env=_safe_env(work_dir),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return _result(
                    "gitleaks",
                    started,
                    version=version,
                    status="partial",
                    eligible_files=files,
                    warnings=("scanner_timeout",),
                )
            except OSError:
                return _result(
                    "gitleaks",
                    started,
                    version=version,
                    status="error",
                    eligible_files=files,
                    warnings=("scanner_failed",),
                )
            try:
                payload = _read_report(report)
                findings = _parse_gitleaks(payload, root, frozenset(files))
            except _InvalidReport as error:
                return _result(
                    "gitleaks",
                    started,
                    version=version,
                    status="error",
                    eligible_files=files,
                    warnings=(str(error),),
                )
            warnings: tuple[str, ...] = ()
            status: ExternalStatus = "completed"
            if completed.returncode != 0:
                warnings = ("scanner_failed",)
                status = "partial"
            if target_ignore_present:
                warnings += ("target_ignore_file_applied",)
                status = "partial"
            return _result(
                "gitleaks",
                started,
                version=version,
                status=status,
                eligible_files=files,
                inspected_files=tuple(
                    sorted(
                        {path for finding in findings if (path := finding.file_path) is not None}
                    )
                ),
                checks=("builtin-default",),
                warnings=warnings,
                findings=findings,
            )


def _parse_gitleaks(payload: object, root: Path, eligible: frozenset[str]) -> tuple[Finding, ...]:
    if not isinstance(payload, list):
        raise _InvalidReport("malformed_report")
    if len(payload) > _MAX_FINDINGS:
        raise _InvalidReport("result_limit_exceeded")
    findings: list[Finding] = []
    for item in payload:
        if not isinstance(item, dict):
            raise _InvalidReport("malformed_report")
        rule = _rule_id(item.get("RuleID"))
        path = _relative_report_path(item.get("File"), root, eligible)
        start = _line(item.get("StartLine"))
        end = _line(item.get("EndLine"), default=start)
        if end < start:
            raise _InvalidReport("invalid_line")
        column = item.get("StartColumn", 1)
        if isinstance(column, bool) or not isinstance(column, int) or column < 1:
            raise _InvalidReport("invalid_line")
        findings.append(
            Finding(
                id=_finding_id("gitleaks", rule, path, start, end, column),
                rule_id=f"GITLEAKS/{rule}",
                category="secret",
                severity=Severity.HIGH,
                file_path=path,
                line_start=start,
                line_end=end,
                message=f"Potential exposed credential detected by Gitleaks rule {rule}.",
                redacted_evidence="[REDACTED: secret value omitted]",
                confidence=Confidence.MEDIUM,
                cwe_ids=("CWE-798",),
                engine="gitleaks",
                remediation=(
                    "Revoke the credential if valid and move the replacement to a secret store."
                ),
            )
        )
    return tuple(findings)


_CONFIG_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
_CONFIG_FILENAMES = {"dockerfile", "containerfile"}


def _config_candidate(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name in {".checkov.yaml", ".checkov.yml"} or is_compose_file(path):
        return False
    return (
        pure.suffix.lower() in _CONFIG_EXTENSIONS
        or name.endswith(".tf.json")
        or name in _CONFIG_FILENAMES
        or name.startswith("dockerfile.")
        or name.startswith("containerfile.")
    )


def _frameworks(files: tuple[str, ...]) -> tuple[str, ...]:
    selected: set[str] = set()
    for path in files:
        pure = PurePosixPath(path)
        name = pure.name.lower()
        if name.endswith((".tf", ".tfvars", ".tf.json")):
            selected.add("terraform")
        if name in _CONFIG_FILENAMES or name.startswith(("dockerfile.", "containerfile.")):
            selected.add("dockerfile")
        if pure.suffix.lower() in {".yaml", ".yml", ".json"}:
            selected.update(("kubernetes", "cloudformation"))
            if path.startswith(".github/workflows/"):
                selected.add("github_actions")
    return tuple(sorted(selected))


def _stage_checkov_input(
    root: Path, staged_root: Path, eligible: tuple[str, ...], deadline: float
) -> None:
    """Copy verified eligible files into a bounded tree inaccessible to target controls."""

    if len(eligible) > _MAX_STAGED_FILES:
        raise _UnsafeSnapshot("input_limit_exceeded")
    try:
        resolved_root = root.resolve(strict=True)
        staged_root.mkdir()
        total_bytes = 0
        for relative in eligible:
            if monotonic() >= deadline:
                raise _StagingTimeout
            pure = PurePosixPath(relative)
            source = root.joinpath(*pure.parts)
            ancestor = root
            for part in pure.parts[:-1]:
                ancestor /= part
                if _is_link_like(ancestor):
                    raise _UnsafeSnapshot("snapshot_contains_link")
            if _is_link_like(source) or not source.is_file():
                raise _UnsafeSnapshot("snapshot_contains_link")
            before = source.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise _UnsafeSnapshot("snapshot_contains_link")
            try:
                source.resolve(strict=True).relative_to(resolved_root)
            except ValueError as error:
                raise _UnsafeSnapshot("snapshot_contains_link") from error
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(source, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                    raise _UnsafeSnapshot("snapshot_changed")
                if opened.st_size + total_bytes > _MAX_STAGED_BYTES:
                    raise _UnsafeSnapshot("input_limit_exceeded")
                with os.fdopen(descriptor, "rb", closefd=False) as source_file:
                    payload = source_file.read(opened.st_size + 1)
                after_open = os.fstat(descriptor)
                after_path = source.stat(follow_symlinks=False)
                if (
                    len(payload) != opened.st_size
                    or (
                        after_open.st_dev,
                        after_open.st_ino,
                        after_open.st_size,
                        after_open.st_mtime_ns,
                    )
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    or (after_path.st_dev, after_path.st_ino) != (opened.st_dev, opened.st_ino)
                ):
                    raise _UnsafeSnapshot("snapshot_changed")
            finally:
                os.close(descriptor)
            if b"\x00" in payload:
                raise _UnsafeSnapshot("invalid_snapshot")
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise _UnsafeSnapshot("invalid_snapshot") from error
            if monotonic() >= deadline:
                raise _StagingTimeout
            destination = staged_root.joinpath(*pure.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            total_bytes += len(payload)
            if monotonic() >= deadline:
                raise _StagingTimeout
    except OSError as error:
        raise _UnsafeSnapshot("invalid_snapshot") from error


@dataclass(frozen=True, slots=True)
class CheckovAdapter:
    """Evaluate built-in static IaC policies without network or custom checks."""

    binary: str = "checkov"

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        started = monotonic()
        try:
            all_files = _snapshot_files(root)
        except _UnsafeSnapshot as error:
            return _result("checkov", started, status="error", warnings=(str(error),))
        root = root.absolute()
        eligible = tuple(path for path in all_files if _config_candidate(path))
        eligible_set = frozenset(eligible)
        skipped = tuple(
            (
                path,
                "scanner_control_file"
                if PurePosixPath(path).name.lower() in {".checkov.yaml", ".checkov.yml"}
                else "unsupported_format",
            )
            for path in all_files
            if path not in eligible_set
        )
        if not eligible:
            return _result(
                "checkov",
                started,
                status="skipped",
                skipped=skipped,
                warnings=("no_eligible_files",),
            )
        if timeout <= 0 or not math.isfinite(timeout):
            return _result(
                "checkov",
                started,
                status="error",
                eligible_files=eligible,
                skipped=skipped,
                warnings=("invalid_timeout",),
            )
        deadline = started + timeout
        binary = shutil.which(self.binary)
        if binary is None:
            return _result(
                "checkov",
                started,
                status="not_run",
                eligible_files=eligible,
                skipped=skipped,
                warnings=("tool_unavailable",),
            )
        with tempfile.TemporaryDirectory(
            prefix="secragraph-checkov-", dir=root.parent
        ) as temporary:
            work_dir = Path(temporary)
            config = work_dir / "trusted.yaml"
            config.write_text("{}\n", encoding="utf-8")
            staged_root = work_dir / "input"
            try:
                _stage_checkov_input(root, staged_root, eligible, deadline)
            except _StagingTimeout:
                return _result(
                    "checkov",
                    started,
                    status="partial",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=("scanner_timeout",),
                )
            except _UnsafeSnapshot as error:
                return _result(
                    "checkov",
                    started,
                    status="error",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=(str(error),),
                )
            version = _probe_version(binary, max(0.0, deadline - monotonic()), work_dir)
            remaining = deadline - monotonic()
            if remaining <= 0:
                return _result(
                    "checkov",
                    started,
                    version=version,
                    status="partial",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=("scanner_timeout",),
                )
            command = [
                binary,
                "--directory",
                str(staged_root),
                "--config-file",
                str(config),
                "--framework",
                *_frameworks(eligible),
                "--skip-download",
                "--skip-results-upload",
                "--download-external-modules",
                "false",
                "--evaluate-variables",
                "false",
                "--soft-fail",
                "--output",
                "json",
            ]
            try:
                with (work_dir / "stdout.json").open("w+b") as output:
                    completed = subprocess.run(  # noqa: S603  # nosec B603
                        command,
                        stdout=output,
                        stderr=subprocess.DEVNULL,
                        timeout=remaining,
                        cwd=str(work_dir),
                        env=_safe_env(work_dir),
                        check=False,
                    )
                    output.flush()
                    payload = _read_report(work_dir / "stdout.json")
            except subprocess.TimeoutExpired:
                return _result(
                    "checkov",
                    started,
                    version=version,
                    status="partial",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=("scanner_timeout",),
                )
            except OSError:
                return _result(
                    "checkov",
                    started,
                    version=version,
                    status="error",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=("scanner_failed",),
                )
            except _InvalidReport as error:
                return _result(
                    "checkov",
                    started,
                    version=version,
                    status="error",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=(str(error),),
                )
            try:
                findings, inspected, checks, parsing_errors, skipped_checks = _parse_checkov(
                    payload, staged_root, eligible_set, frozenset(_frameworks(eligible))
                )
            except _InvalidReport as error:
                return _result(
                    "checkov",
                    started,
                    version=version,
                    status="error",
                    eligible_files=eligible,
                    skipped=skipped,
                    warnings=(str(error),),
                )
            warnings: list[str] = []
            if completed.returncode != 0:
                warnings.append("scanner_failed")
            if parsing_errors:
                warnings.append("parsing_errors")
            if skipped_checks:
                warnings.append("checks_skipped")
            if not inspected:
                warnings.append("no_file_coverage")
            unconfirmed = tuple(sorted(set(eligible) - set(inspected)))
            if unconfirmed:
                warnings.append("unconfirmed_files")
                skipped += tuple((path, "not_confirmed_by_tool") for path in unconfirmed)
            status: ExternalStatus = "partial" if warnings else "completed"
            return _result(
                "checkov",
                started,
                version=version,
                status=status,
                eligible_files=eligible,
                inspected_files=inspected,
                skipped=skipped,
                checks=checks,
                warnings=tuple(warnings),
                findings=findings,
            )


def _parse_checkov(
    payload: object,
    root: Path,
    eligible: frozenset[str],
    frameworks: frozenset[str],
) -> tuple[tuple[Finding, ...], tuple[str, ...], tuple[str, ...], bool, bool]:
    reports = payload if isinstance(payload, list) else [payload]
    if not reports or not all(isinstance(report, dict) for report in reports):
        raise _InvalidReport("malformed_report")
    findings: list[Finding] = []
    inspected: set[str] = set()
    checks: set[str] = set()
    parsing_errors = False
    skipped_checks = False
    total_records = 0
    for report in reports:
        if not isinstance(report, dict):
            raise _InvalidReport("malformed_report")
        if report.get("check_type") not in frameworks:
            raise _InvalidReport("unexpected_framework")
        results = report.get("results")
        summary = report.get("summary")
        if not isinstance(results, dict) or not isinstance(summary, dict):
            raise _InvalidReport("malformed_report")
        failed = results.get("failed_checks")
        passed = results.get("passed_checks")
        skipped = results.get("skipped_checks")
        errors = results.get("parsing_errors")
        if (
            not isinstance(failed, list)
            or not isinstance(passed, list)
            or not isinstance(skipped, list)
            or not isinstance(errors, list)
        ):
            raise _InvalidReport("malformed_report")
        total_records += len(failed) + len(passed) + len(skipped) + len(errors)
        if total_records > _MAX_CHECKOV_RECORDS or len(findings) + len(failed) > _MAX_FINDINGS:
            raise _InvalidReport("result_limit_exceeded")
        error_count = summary.get("parsing_errors", 0)
        skip_count = summary.get("skipped", 0)
        parsing_errors |= bool(errors) or (isinstance(error_count, int) and error_count > 0)
        skipped_checks |= bool(skipped) or (isinstance(skip_count, int) and skip_count > 0)
        for is_failure, records in ((True, failed), (False, passed)):
            for record in records:
                if not isinstance(record, dict):
                    raise _InvalidReport("malformed_report")
                rule = _rule_id(record.get("check_id"))
                absolute_path = record.get("file_abs_path")
                if isinstance(absolute_path, str) and absolute_path:
                    path = _relative_report_path(absolute_path, root, eligible)
                else:
                    path = _relative_report_path(
                        record.get("file_path"), root, eligible, root_relative_slash=True
                    )
                inspected.add(path)
                checks.add(rule)
                if len(checks) > _MAX_CHECKS:
                    raise _InvalidReport("result_limit_exceeded")
                if not is_failure:
                    continue
                line_range = record.get("file_line_range")
                if isinstance(line_range, list) and len(line_range) >= 2:
                    start = _line(line_range[0], default=1)
                    end = _line(line_range[1], default=start)
                else:
                    start = end = 1
                if end < start:
                    end = start
                severity_value = record.get("severity")
                severity = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFO": Severity.INFO,
                }.get(str(severity_value).upper(), Severity.MEDIUM)
                resource = record.get("resource")
                resource_identity = resource if isinstance(resource, str) else ""
                findings.append(
                    Finding(
                        id=_finding_id("checkov", rule, path, start, end, resource_identity),
                        rule_id=f"CHECKOV/{rule}",
                        category="configuration",
                        severity=severity,
                        file_path=path,
                        line_start=start,
                        line_end=end,
                        message=f"Configuration policy {rule} failed.",
                        redacted_evidence="[REDACTED: configuration snippet omitted]",
                        confidence=Confidence.MEDIUM,
                        engine="checkov",
                        remediation=(
                            "Review the failed Checkov policy and apply a secure configuration."
                        ),
                    )
                )
    return (
        tuple(findings),
        tuple(sorted(inspected)),
        tuple(sorted(checks)),
        parsing_errors,
        skipped_checks,
    )
