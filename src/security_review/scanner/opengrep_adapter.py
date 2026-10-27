"""Opengrep SAST adapter using a pinned, permissively licensed rule bundle."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import tempfile
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import Literal

from security_review.domain.models import Confidence, Finding, Severity, TraceLocation
from security_review.scanner.external_common import (
    ExternalExecution,
    ExternalScanResult,
    ExternalStatus,
)

_SOURCE_EXTENSIONS = frozenset({".py", ".js", ".jsx", ".ts", ".tsx"})
_MAX_OUTPUT_BYTES = 32_000_000
_MAX_RESULTS = 2_000
_RULE_ID = re.compile(r"[A-Za-z0-9_.-]{1,180}\Z")
_CWE_ID = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")


def _default_rules(name: str) -> Path:
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "data" / "engines" / name
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parents[3] / "data" / "engines" / name


_DEFAULT_RULES = _default_rules("opengrep")
_DEFAULT_TAINT_RULES = _default_rules("secragraph-taint")


class _UnsafeReport(ValueError):
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


def _eligible_paths(root: Path) -> tuple[str, ...]:
    if _is_link_like(root) or not root.is_dir():
        raise _UnsafeReport("invalid_snapshot")
    eligible: list[str] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        for name in dirs:
            if _is_link_like(here / name):
                raise _UnsafeReport("snapshot_contains_link")
        for name in files:
            path = here / name
            if _is_link_like(path):
                raise _UnsafeReport("snapshot_contains_link")
            if path.suffix.lower() in _SOURCE_EXTENSIONS:
                eligible.append(path.relative_to(root).as_posix())
    return tuple(sorted(eligible))


def _relative_path(raw: object, root: Path, eligible: set[str]) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 2_048 or "\x00" in raw:
        raise _UnsafeReport("invalid_result_path")
    normalized = raw.replace("\\", "/")
    logical = PurePosixPath(normalized)
    if ".." in logical.parts:
        raise _UnsafeReport("outside_snapshot")
    candidate = Path(raw)
    if not candidate.is_absolute():
        if ":" in logical.parts[0]:
            raise _UnsafeReport("outside_snapshot")
        candidate = root.joinpath(*logical.parts)
    try:
        relative = candidate.resolve(strict=False).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as error:
        raise _UnsafeReport("outside_snapshot") from error
    if relative not in eligible:
        raise _UnsafeReport("unsubmitted_result_path")
    return relative


def _line(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000:
        raise _UnsafeReport("invalid_result_line")
    return value


def _cwes(metadata: object) -> tuple[str, ...]:
    if not isinstance(metadata, dict):
        return ()
    raw = metadata.get("cwe", ())
    values = (raw,) if isinstance(raw, str) else raw
    if not isinstance(values, (tuple, list)):
        return ()
    return tuple(
        dict.fromkeys(item for item in values if isinstance(item, str) and _CWE_ID.fullmatch(item))
    )[:8]


def _severity(value: object) -> Severity:
    return {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}.get(
        value if isinstance(value, str) else "", Severity.MEDIUM
    )


def _message(metadata: object, rule_id: str) -> str:
    if isinstance(metadata, dict):
        value = metadata.get("shortDescription")
        if isinstance(value, str):
            compact = " ".join(value.split())
            if 1 <= len(compact) <= 200 and all(ord(char) >= 32 for char in compact):
                return compact
    return f"Opengrep rule {rule_id} matched source code."


def _trace_location(
    raw: object, role: Literal["source", "step", "sink"], root: Path, eligible: set[str]
) -> TraceLocation | None:
    if not isinstance(raw, dict):
        return None
    try:
        path = _relative_path(raw.get("path"), root, eligible)
        start = raw.get("start")
        if not isinstance(start, dict):
            return None
        line_start = _line(start.get("line"))
        end = raw.get("end")
        line_end = _line(end.get("line")) if isinstance(end, dict) else line_start
        if line_end < line_start:
            return None
        return TraceLocation(file_path=path, line_start=line_start, line_end=line_end, role=role)
    except (OSError, ValueError, _UnsafeReport):
        return None


def _trace_endpoint(
    raw: object, role: Literal["source", "sink"], root: Path, eligible: set[str]
) -> TraceLocation | None:
    if (
        not isinstance(raw, list)
        or len(raw) != 2
        or raw[0] != "CliLoc"
        or not isinstance(raw[1], list)
        or not raw[1]
    ):
        return None
    return _trace_location(raw[1][0], role, root, eligible)


def _taint_trace(raw: object, root: Path, eligible: set[str]) -> tuple[TraceLocation, ...]:
    if not isinstance(raw, dict):
        return ()
    source = _trace_endpoint(raw.get("taint_source"), "source", root, eligible)
    sink = _trace_endpoint(raw.get("taint_sink"), "sink", root, eligible)
    if source is None or sink is None:
        return ()
    middle = raw.get("intermediate_vars", [])
    if not isinstance(middle, list):
        middle = []
    steps = tuple(
        location
        for item in middle[:62]
        if isinstance(item, dict)
        if (location := _trace_location(item.get("location"), "step", root, eligible)) is not None
    )
    return (source, *steps, sink)


def _normalize_report(
    payload: object, root: Path, eligible_files: tuple[str, ...]
) -> tuple[tuple[Finding, ...], tuple[str, ...], bool]:
    if not isinstance(payload, dict):
        raise _UnsafeReport("invalid_report")
    results = payload.get("results")
    errors = payload.get("errors")
    paths = payload.get("paths")
    if (
        not isinstance(results, list)
        or len(results) > _MAX_RESULTS
        or not isinstance(errors, list)
        or not isinstance(paths, dict)
        or not isinstance(paths.get("scanned"), list)
    ):
        raise _UnsafeReport("invalid_report")
    eligible = set(eligible_files)
    inspected = tuple(
        dict.fromkeys(_relative_path(path, root, eligible) for path in paths["scanned"])
    )
    skipped = paths.get("skipped", [])
    if not isinstance(skipped, list):
        raise _UnsafeReport("invalid_report")
    findings: list[Finding] = []
    for item in results:
        if not isinstance(item, dict):
            raise _UnsafeReport("invalid_result")
        raw_rule = item.get("check_id")
        if not isinstance(raw_rule, str) or not _RULE_ID.fullmatch(raw_rule):
            raise _UnsafeReport("invalid_rule_id")
        short_rule = raw_rule.rsplit(".", 1)[-1]
        if len(short_rule) > 110:
            short_rule = f"{short_rule[:96]}-{sha256(raw_rule.encode()).hexdigest()[:12]}"
        file_path = _relative_path(item.get("path"), root, eligible)
        start = item.get("start")
        end = item.get("end")
        if not isinstance(start, dict):
            raise _UnsafeReport("invalid_result_line")
        line_start = _line(start.get("line"))
        line_end = _line(end.get("line")) if isinstance(end, dict) else line_start
        if line_end < line_start:
            raise _UnsafeReport("invalid_result_line")
        extra = item.get("extra")
        if not isinstance(extra, dict):
            raise _UnsafeReport("invalid_result")
        rule_id = f"OG/{short_rule}"
        identifier = sha256(f"{rule_id}\0{file_path}\0{line_start}".encode()).hexdigest()[:20]
        findings.append(
            Finding(
                id=f"{rule_id}:{identifier}",
                rule_id=rule_id,
                category="sast",
                severity=_severity(extra.get("severity")),
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                message=_message(extra.get("metadata"), rule_id),
                redacted_evidence="[source omitted]",
                confidence=Confidence.MEDIUM,
                cwe_ids=_cwes(extra.get("metadata")),
                remediation=(
                    "Review the reported flow and replace unsafe operations with validated, "
                    "parameterized APIs."
                ),
                engine="opengrep",
                trace=_taint_trace(extra.get("dataflow_trace"), root, eligible),
            )
        )
    partial = bool(errors or skipped or set(inspected) != eligible)
    return tuple(findings), inspected, partial


def _safe_env(home: Path) -> dict[str, str]:
    retained = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "LD_LIBRARY_PATH")
    environment = {key: os.environ[key] for key in retained if key in os.environ}
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(home),
            "LOCALAPPDATA": str(home),
            "XDG_CACHE_HOME": str(home),
            "XDG_CONFIG_HOME": str(home),
            "TEMP": str(home),
            "TMP": str(home),
            "TMPDIR": str(home),
            "OPENGREP_ENABLE_VERSION_CHECK": "false",
            "SEMGREP_SEND_METRICS": "off",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
        }
    )
    return environment


class OpengrepAdapter:
    """Run local Opengrep rules without forwarding target config or source output."""

    def __init__(
        self,
        binary: str = "opengrep",
        rules_root: Path = _DEFAULT_RULES,
        taint_rules_root: Path = _DEFAULT_TAINT_RULES,
    ) -> None:
        self.binary = binary
        self.rules_root = rules_root
        self.taint_rules_root = taint_rules_root

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        started = monotonic()
        eligible = _eligible_paths(root)

        def result(
            status: ExternalStatus,
            *,
            findings: tuple[Finding, ...] = (),
            inspected: tuple[str, ...] = (),
            version: str | None = None,
            warning: str = "",
        ) -> ExternalScanResult:
            return ExternalScanResult(
                findings=findings,
                execution=ExternalExecution(
                    scanner="opengrep",
                    version=version,
                    status=status,
                    eligible_files=eligible,
                    inspected_files=inspected,
                    checks=(
                        "patched-codes-mit-rules@1118d79823ae",
                        "OG/python-web-command-taint",
                        "OG/python-web-sql-taint",
                        "OG/javascript-web-command-taint",
                    ),
                    duration_ms=max(0, round((monotonic() - started) * 1000)),
                    warnings=(warning,) if warning else (),
                ),
            )

        if not eligible:
            return result("skipped", warning="no_sast_files")
        executable = shutil.which(self.binary)
        if executable is None:
            return result("not_run", warning="tool_unavailable")
        python_rules = self.rules_root / "python"
        javascript_rules = self.rules_root / "javascript"
        if (
            not python_rules.is_dir()
            or not javascript_rules.is_dir()
            or not (self.taint_rules_root / "python.yml").is_file()
            or not (self.taint_rules_root / "javascript.yml").is_file()
        ):
            return result("not_run", warning="rules_unavailable")
        if timeout <= 0 or not math.isfinite(timeout):
            return result("not_run", warning="scan_deadline_exceeded")
        deadline = started + timeout
        with tempfile.TemporaryDirectory(prefix="secragraph-opengrep-") as temporary:
            work = Path(temporary)
            environment = _safe_env(work)
            try:
                probe = subprocess.run(  # noqa: S603  # nosec B603
                    [executable, "--version"],
                    cwd=work,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=min(max(0.0, deadline - monotonic()), 10),
                    check=False,
                )
                raw_version = probe.stdout.strip()
                version = (
                    raw_version
                    if probe.returncode == 0 and _VERSION.fullmatch(raw_version)
                    else None
                )
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return result("partial", version=version, warning="tool_timeout")
                output = work / "report.json"
                command = [
                    executable,
                    "scan",
                    "--config",
                    str(python_rules),
                    "--config",
                    str(javascript_rules),
                    "--config",
                    str(self.taint_rules_root),
                    "--json-output",
                    str(output),
                    "--quiet",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--disable-nosem",
                    "--taint-intrafile",
                    "--jobs",
                    "1",
                    "--timeout",
                    "5",
                    "--max-target-bytes",
                    "1000000",
                    ".",
                ]
                completed = subprocess.run(  # noqa: S603  # nosec B603
                    command,
                    cwd=root,
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=remaining,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return result("partial", warning="tool_timeout")
            except OSError:
                return result("error", warning="tool_failed")
            try:
                with output.open("rb") as stream:
                    body = stream.read(_MAX_OUTPUT_BYTES + 1)
                if len(body) > _MAX_OUTPUT_BYTES:
                    raise _UnsafeReport("report_too_large")
                findings, inspected, partial = _normalize_report(
                    json.loads(body.decode("utf-8")), root, eligible
                )
            except (OSError, UnicodeError, json.JSONDecodeError, _UnsafeReport):
                return result("error", version=version, warning="invalid_tool_report")
            if completed.returncode != 0:
                return result(
                    "partial",
                    findings=findings,
                    inspected=inspected,
                    version=version,
                    warning="tool_nonzero_exit",
                )
            if partial:
                return result(
                    "partial",
                    findings=findings,
                    inspected=inspected,
                    version=version,
                    warning="scan_partial",
                )
            return result("completed", findings=findings, inspected=inspected, version=version)
