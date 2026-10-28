"""Run passive ZAP DAST only against explicitly disposable Docker containers."""

from __future__ import annotations

import os
import re
import secrets
import subprocess  # nosec B404
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Literal

from security_review.dast.zap import (
    MAX_OPENAPI_BYTES,
    MAX_ZAP_REPORT_BYTES,
    DastInputError,
    DastReportError,
    parse_zap_report,
    sanitize_openapi,
)
from security_review.domain.models import Finding, ScanExecution

ZAP_IMAGE = (
    "ghcr.io/zaproxy/zaproxy:stable@"
    "sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
)
_MAX_DURATION_SECONDS = 300.0
_DOCKER_SETUP_SECONDS = 15.0
_HELPER_SECONDS = 15.0
_DOCKER_CLEANUP_SECONDS = 15.0
_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_OPENAPI_PATH = re.compile(r"/[A-Za-z0-9/._~-]{1,255}\Z")
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
_LABEL = "io.secragraph.dast.disposable"
_ALIAS = "secragraph-target"
_FETCH_SCRIPT = """
import sys
import urllib.request

class RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect_not_allowed")

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirect())
with opener.open(sys.argv[1], timeout=7) as response:
    if response.status != 200:
        raise ValueError("openapi_http_status")
    payload = response.read(2000001)
    if len(payload) > 2000000:
        raise ValueError("openapi_size_limit")
sys.stdout.buffer.write(payload)
""".strip()


class DastScanError(ValueError):
    """Safe, code-only refusal before a DAST scan is allowed to start."""


@dataclass(frozen=True, slots=True)
class DastScanResult:
    """Normalized DAST output and truthful execution coverage."""

    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]
    execution: ScanExecution


def _docker(
    args: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603  # nosec B603, B607
        ["docker", *args],  # noqa: S607 - Docker is the required local runtime
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        env=env,
        check=False,
    )


def _validate(
    container: str, port: int, openapi_path: str, auth_header_env: str | None
) -> str | None:
    if not isinstance(container, str) or not _CONTAINER_NAME.fullmatch(container):
        raise DastScanError("invalid_dast_container")
    if type(port) is not int or not 1 <= port <= 65535:
        raise DastScanError("invalid_dast_port")
    if (
        not isinstance(openapi_path, str)
        or not _OPENAPI_PATH.fullmatch(openapi_path)
        or "//" in openapi_path
        or "/./" in openapi_path
        or "/../" in openapi_path
        or openapi_path.endswith(("/.", "/.."))
    ):
        raise DastScanError("invalid_dast_openapi_path")
    if auth_header_env is None:
        return None
    if not isinstance(auth_header_env, str) or not _ENV_NAME.fullmatch(auth_header_env):
        raise DastScanError("invalid_dast_auth_env")
    value = os.environ.get(auth_header_env)
    if (
        value is None
        or not 1 <= len(value) <= 2_048
        or value != value.strip()
        or any(
            ord(character) < 32 or ord(character) > 126 or character == "," for character in value
        )
    ):
        raise DastScanError("invalid_dast_auth_header")
    return value


def _inspect_target(container: str) -> None:
    try:
        running = _docker(
            ["inspect", "--format", "{{.State.Running}}", container],
            timeout=_DOCKER_SETUP_SECONDS,
            capture=True,
        )
        label = _docker(
            ["inspect", "--format", f'{{{{index .Config.Labels "{_LABEL}"}}}}', container],
            timeout=_DOCKER_SETUP_SECONDS,
            capture=True,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DastScanError("dast_target_unavailable") from error
    if running.returncode != 0 or (running.stdout or b"").strip() != b"true":
        raise DastScanError("dast_target_unavailable")
    if label.returncode != 0 or (label.stdout or b"").strip() != b"true":
        raise DastScanError("target_not_disposable")


def _execution(
    *,
    status: Literal["completed", "partial", "error"],
    started: float,
    eligible: tuple[str, ...],
    findings: tuple[Finding, ...],
    reason: str | None = None,
) -> ScanExecution:
    return ScanExecution(
        engine="zap",
        kind="dast",
        status=status,
        version=ZAP_IMAGE,
        elapsed_ms=max(0, int((monotonic() - started) * 1_000)),
        checks=("openapi-passive",),
        eligible_endpoints=eligible,
        observed_alert_endpoints=tuple(
            sorted({f"{item.http_method} {item.http_path}" for item in findings})
        ),
        reason=reason,
    )


def _result(
    *,
    started: float,
    status: Literal["completed", "partial", "error"],
    eligible: tuple[str, ...] = (),
    findings: tuple[Finding, ...] = (),
    reason: str | None = None,
) -> DastScanResult:
    warnings = ("dast_passive_only",) if reason is None else ("dast_passive_only", reason)
    return DastScanResult(
        findings=findings,
        warnings=warnings,
        execution=_execution(
            status=status, started=started, eligible=eligible, findings=findings, reason=reason
        ),
    )


def _cleanup(args: list[str]) -> bool:
    try:
        return _docker(args, timeout=_DOCKER_CLEANUP_SECONDS).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_zap_api_scan(
    container: str,
    port: int,
    openapi_path: str,
    *,
    auth_header_env: str | None = None,
) -> DastScanResult:
    """Scan a labelled, running Docker test API with a scope-limited passive ZAP."""

    auth_value = _validate(container, port, openapi_path, auth_header_env)
    _inspect_target(container)
    started = monotonic()
    deadline = started + _MAX_DURATION_SECONDS
    nonce = secrets.token_hex(8)
    network = f"secragraph-dast-{nonce}"
    helper_name = f"secragraph-dast-fetch-{nonce}"
    zap_name = f"secragraph-dast-zap-{nonce}"
    origin = f"http://{_ALIAS}:{port}"
    network_attempted = False
    connect_attempted = False
    helper_attempted = False
    zap_attempted = False
    eligible: tuple[str, ...] = ()
    outcome: DastScanResult | None = None
    cleanup_failed = False

    with tempfile.TemporaryDirectory(prefix="secragraph-dast-") as directory:
        working = Path(directory)
        try:
            network_attempted = True
            created = _docker(
                ["network", "create", "--internal", "--driver", "bridge", network],
                timeout=min(_DOCKER_SETUP_SECONDS, max(0.1, deadline - monotonic())),
            )
            if created.returncode != 0:
                outcome = _result(started=started, status="error", reason="dast_network_failed")
            else:
                connect_attempted = True
                connected = _docker(
                    ["network", "connect", "--alias", _ALIAS, network, container],
                    timeout=min(_DOCKER_SETUP_SECONDS, max(0.1, deadline - monotonic())),
                )
                if connected.returncode != 0:
                    outcome = _result(started=started, status="error", reason="dast_connect_failed")
                else:
                    helper_attempted = True
                    helper = _docker(
                        [
                            "run",
                            "--name",
                            helper_name,
                            "--network",
                            network,
                            "--read-only",
                            "--cap-drop",
                            "ALL",
                            "--security-opt",
                            "no-new-privileges",
                            "--pids-limit",
                            "64",
                            "--memory",
                            "256m",
                            "--entrypoint",
                            "python3",
                            ZAP_IMAGE,
                            "-I",
                            "-B",
                            "-c",
                            _FETCH_SCRIPT,
                            f"{origin}{openapi_path}",
                        ],
                        timeout=min(_HELPER_SECONDS, max(0.1, deadline - monotonic())),
                        capture=True,
                    )
                    if helper.returncode != 0 or not helper.stdout:
                        outcome = _result(
                            started=started, status="error", reason="dast_openapi_fetch_failed"
                        )
                    elif len(helper.stdout) > MAX_OPENAPI_BYTES:
                        outcome = _result(
                            started=started, status="error", reason="dast_openapi_size_limit"
                        )
                    else:
                        try:
                            safe = sanitize_openapi(helper.stdout, origin=origin)
                        except DastInputError:
                            outcome = _result(
                                started=started, status="error", reason="dast_openapi_invalid"
                            )
                        else:
                            eligible = safe.eligible_endpoints
                            (working / "openapi.json").write_bytes(safe.document)
                            child_env = dict(os.environ)
                            child_env["ZAP_AUTH_HEADER_SITE"] = _ALIAS
                            zap_args = [
                                "run",
                                "--name",
                                zap_name,
                                "--network",
                                network,
                                "--cap-drop",
                                "ALL",
                                "--security-opt",
                                "no-new-privileges",
                                "--pids-limit",
                                "256",
                                "--memory",
                                "2g",
                                "--cpus",
                                "2",
                                "--mount",
                                f"type=bind,src={working},dst=/zap/wrk",
                            ]
                            if auth_value is not None:
                                child_env["ZAP_AUTH_HEADER_VALUE"] = auth_value
                                zap_args.extend(["-e", "ZAP_AUTH_HEADER_VALUE"])
                            zap_args.extend(
                                [
                                    "-e",
                                    "ZAP_AUTH_HEADER_SITE",
                                    ZAP_IMAGE,
                                    "zap-api-scan.py",
                                    "-t",
                                    "/zap/wrk/openapi.json",
                                    "-f",
                                    "openapi",
                                    "-S",
                                    "-J",
                                    "/zap/wrk/zap.json",
                                    "-T",
                                    "3",
                                    "-z",
                                    "-silent",
                                ]
                            )
                            zap_attempted = True
                            scan = _docker(
                                zap_args,
                                timeout=max(0.1, deadline - monotonic()),
                                env=child_env,
                            )
                            if scan.returncode not in {0, 1, 2}:
                                outcome = _result(
                                    started=started,
                                    status="error",
                                    eligible=eligible,
                                    reason="dast_zap_failed",
                                )
                            else:
                                report_file = working / "zap.json"
                                try:
                                    with report_file.open("rb") as stream:
                                        raw_report = stream.read(MAX_ZAP_REPORT_BYTES + 1)
                                    findings = parse_zap_report(
                                        raw_report,
                                        origin=origin,
                                        eligible_endpoints=eligible,
                                        deadline=deadline,
                                    )
                                except DastReportError as error:
                                    timed_out = str(error) == "zap_report_timeout"
                                    outcome = _result(
                                        started=started,
                                        status="partial" if timed_out else "error",
                                        eligible=eligible,
                                        reason="dast_scan_timeout"
                                        if timed_out
                                        else "dast_report_invalid",
                                    )
                                except OSError:
                                    outcome = _result(
                                        started=started,
                                        status="error",
                                        eligible=eligible,
                                        reason="dast_report_invalid",
                                    )
                                else:
                                    outcome = _result(
                                        started=started,
                                        status="completed",
                                        eligible=eligible,
                                        findings=findings,
                                    )
        except subprocess.TimeoutExpired:
            outcome = _result(
                started=started, status="partial", eligible=eligible, reason="dast_scan_timeout"
            )
        except OSError:
            outcome = _result(
                started=started, status="error", eligible=eligible, reason="dast_docker_failed"
            )
        finally:
            if zap_attempted and not _cleanup(["container", "rm", "-f", zap_name]):
                cleanup_failed = True
            if helper_attempted and not _cleanup(["container", "rm", "-f", helper_name]):
                cleanup_failed = True
            if connect_attempted and not _cleanup(
                ["network", "disconnect", "--force", network, container]
            ):
                cleanup_failed = True
            if network_attempted and not _cleanup(["network", "rm", network]):
                cleanup_failed = True
    if outcome is None:
        outcome = _result(started=started, status="error", reason="dast_unknown_failure")
    if cleanup_failed:
        return DastScanResult(
            findings=outcome.findings,
            warnings=(*outcome.warnings, "dast_cleanup_failed"),
            execution=outcome.execution.model_copy(
                update={"status": "error", "reason": "dast_cleanup_failed"}
            ),
        )
    return outcome
