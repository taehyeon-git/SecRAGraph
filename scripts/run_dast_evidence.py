"""Prove passive and active DAST against one isolated disposable API fixture."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from threading import Thread
from time import monotonic
from urllib.parse import urlencode
from uuid import uuid4

from security_review.dast.runner import ZAP_IMAGE, _network_isolated, prepare_zap_image
from security_review.domain.models import ScanReport
from security_review.reporting.types import ReportFormat, render_report

_ROOT = Path(__file__).resolve().parents[1]
_COMPOSE_FILE = _ROOT / "infra" / "dast" / "compose.yaml"
_DEFAULT_OUTPUT = _ROOT / "build" / "evidence"
_ARTIFACT_NAMES = (
    "dast.json",
    "dast.md",
    "dast.sarif",
    "dast-active.json",
    "dast-active.md",
    "dast-active.sarif",
)
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_UNSET = object()
_SAFE_FAILURE_CODES = frozenset(
    {
        "active_execution_missing",
        "active_safe_control_alert",
        "active_safe_route_not_attacked",
        "active_sql_alert_missing",
        "active_vulnerable_route_not_attacked",
        "dast_active_scan_incomplete",
        "authenticated_route_not_tested",
        "credential_in_report",
        "dast_cleanup_failed",
        "dast_connect_failed",
        "dast_docker_failed",
        "dast_incomplete",
        "dast_openapi_fetch_failed",
        "dast_openapi_invalid",
        "dast_openapi_size_limit",
        "dast_report_invalid",
        "dast_scan_timeout",
        "dast_scope_violation",
        "dast_network_failed",
        "dast_network_isolation_failed",
        "dast_unknown_failure",
        "dast_zap_failed",
        "dast_zap_image_unavailable",
        "docker_unavailable",
        "expected_alert_missing",
        "public_route_not_tested",
        "fixture_cleanup_failed",
        "fixture_container_unavailable",
        "fixture_probe_failed",
        "fixture_start_failed",
        "fixture_unhealthy",
        "host_redirect_escaped",
        "redirect_probe_cleanup_failed",
        "redirect_probe_control_failed",
        "redirect_probe_isolation_failed",
        "redirect_probe_network_unavailable",
        "redirect_probe_target_unavailable",
        "zap_image_unavailable",
    }
)
_REDIRECT_FETCH = "\n".join(
    (
        "import sys, urllib.request",
        "opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))",
        "with opener.open(sys.argv[1], timeout=6) as response:",
        "    response.read(1)",
    )
)
_FIXTURE_FETCH = "\n".join(
    (
        "import sys, urllib.request",
        "url = 'http://127.0.0.1:8000' + sys.argv[1]",
        "with urllib.request.urlopen(url, timeout=4) as response:",
        "    data = response.read(4097)",
        "if len(data) > 4096:",
        "    raise SystemExit(2)",
        "sys.stdout.buffer.write(data)",
    )
)


def _docker_executable() -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker_unavailable")
    return docker


def _prepare_zap_image() -> None:
    """Allow a bounded image pull before short Docker helper deadlines begin."""

    if not prepare_zap_image(monotonic() + 240):
        raise RuntimeError("zap_image_unavailable")


def _run_compose(
    project: str, arguments: list[str], environment: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [_docker_executable(), "compose", "-f", str(_COMPOSE_FILE), "-p", project, *arguments],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,  # nosec B603
    )


def _fixture_container(project: str, environment: dict[str, str]) -> str:
    completed = _run_compose(project, ["ps", "-q", "target"], environment, 20)
    container = completed.stdout.strip()
    if completed.returncode != 0 or _CONTAINER_ID.fullmatch(container) is None:
        raise RuntimeError("fixture_container_unavailable")
    return container


def _run_docker(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [_docker_executable(), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,  # nosec B603
    )


def _cleanup_docker(args: list[str]) -> bool:
    try:
        return _run_docker(args).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _network_gateway(network: str) -> str:
    inspected = _run_docker(["network", "inspect", network])
    if inspected.returncode != 0 or len(inspected.stdout) > 65_536:
        raise RuntimeError("redirect_probe_network_unavailable")
    try:
        payload = json.loads(inspected.stdout)
        configs = payload[0]["IPAM"]["Config"]
        gateway = configs[0]["Gateway"]
        address = IPv4Address(gateway)
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError("redirect_probe_network_unavailable") from error
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise RuntimeError("redirect_probe_network_unavailable")
    return str(address)


def _probe_request(network: str, name: str, url: str) -> int:
    try:
        completed = _run_docker(
            [
                "run",
                "--name",
                name,
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
                _REDIRECT_FETCH,
                url,
            ],
            timeout=20,
        )
        return completed.returncode
    finally:
        if not _cleanup_docker(["container", "rm", "-f", name]):
            raise RuntimeError("redirect_probe_cleanup_failed")


def _assert_host_redirect_isolated(container: str) -> None:
    """On Linux CI, prove a host-gateway redirect cannot escape the scan network."""

    if sys.platform != "linux":
        return
    nonce = uuid4().hex[:12]
    baseline = f"secragraph-dast-control-{nonce}"
    isolated = f"secragraph-dast-probe-{nonce}"
    baseline_created = False
    isolated_created = False
    baseline_target_connect_attempted = False
    target_connect_attempted = False
    server: ThreadingHTTPServer | None = None
    thread: Thread | None = None
    marker_hits: list[int] = []
    cleanup_failed = False

    class Marker(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            marker_hits.append(1)
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    try:
        baseline_created = True
        if (
            _run_docker(
                ["network", "create", "--internal", "--driver", "bridge", baseline]
            ).returncode
            != 0
        ):
            raise RuntimeError("redirect_probe_network_unavailable")
        gateway = _network_gateway(baseline)
        server = ThreadingHTTPServer((gateway, 0), Marker)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        marker_url = f"http://{gateway}:{server.server_port}/marker"
        redirect_url = "http://secragraph-target:8000/host-redirect?" + urlencode(
            {"to": marker_url}
        )
        baseline_target_connect_attempted = True
        if (
            _run_docker(
                ["network", "connect", "--alias", "secragraph-target", baseline, container]
            ).returncode
            != 0
        ):
            raise RuntimeError("redirect_probe_target_unavailable")
        control_before = _fetch_fixture_json(container, "/stats").get("host_redirect_requests")
        if _probe_request(baseline, f"secragraph-dast-control-fetch-{nonce}", redirect_url) != 0:
            raise RuntimeError("redirect_probe_control_failed")
        control_after = _fetch_fixture_json(container, "/stats").get("host_redirect_requests")
        if (
            not isinstance(control_before, int)
            or not isinstance(control_after, int)
            or control_after <= control_before
            or len(marker_hits) != 1
        ):
            raise RuntimeError("redirect_probe_control_failed")
        if not _cleanup_docker(["network", "disconnect", "--force", baseline, container]):
            raise RuntimeError("redirect_probe_cleanup_failed")
        baseline_target_connect_attempted = False

        isolated_created = True
        created = _run_docker(
            [
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv6=isolated",
                isolated,
            ]
        )
        if created.returncode != 0 or not _network_isolated(isolated, monotonic() + 15):
            raise RuntimeError("redirect_probe_isolation_failed")
        target_connect_attempted = True
        if (
            _run_docker(
                ["network", "connect", "--alias", "secragraph-target", isolated, container]
            ).returncode
            != 0
        ):
            raise RuntimeError("redirect_probe_target_unavailable")
        before = _fetch_fixture_json(container, "/stats").get("host_redirect_requests")
        response_code = _probe_request(
            isolated, f"secragraph-dast-probe-fetch-{nonce}", redirect_url
        )
        after = _fetch_fixture_json(container, "/stats").get("host_redirect_requests")
        if not isinstance(before, int) or not isinstance(after, int) or after <= before:
            raise RuntimeError("redirect_probe_target_unavailable")
        if response_code == 0 or len(marker_hits) != 1:
            raise RuntimeError("host_redirect_escaped")
    finally:
        if target_connect_attempted and not _cleanup_docker(
            ["network", "disconnect", "--force", isolated, container]
        ):
            cleanup_failed = True
        if isolated_created and not _cleanup_docker(["network", "rm", isolated]):
            cleanup_failed = True
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                cleanup_failed = True
            try:
                server.server_close()
            except Exception:
                cleanup_failed = True
        if thread is not None:
            try:
                thread.join(timeout=5)
            except RuntimeError:
                cleanup_failed = True
        if baseline_target_connect_attempted and not _cleanup_docker(
            ["network", "disconnect", "--force", baseline, container]
        ):
            cleanup_failed = True
        if baseline_created and not _cleanup_docker(["network", "rm", baseline]):
            cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("redirect_probe_cleanup_failed")


def _fetch_fixture_json(container: str, path: str) -> dict[str, object]:
    if path not in {"/health", "/stats"}:
        raise ValueError("unsupported_fixture_probe")
    completed = subprocess.run(  # noqa: S603
        [
            _docker_executable(),
            "exec",
            container,
            "/app/.venv/bin/python",
            "-c",
            _FIXTURE_FETCH,
            path,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
        shell=False,  # nosec B603
    )
    if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 4096:
        raise RuntimeError("fixture_probe_failed")
    try:
        payload = json.loads(completed.stdout)
    except (ValueError, TypeError) as error:
        raise RuntimeError("fixture_probe_failed") from error
    if not isinstance(payload, dict):
        raise RuntimeError("fixture_probe_failed")
    return payload


def _scan(
    container: str,
    port: int,
    openapi_path: str,
    *,
    auth_header_env: str,
    active: bool = False,
) -> ScanReport:
    from security_review.dast.application import scan_dast_container

    return scan_dast_container(
        container, port, openapi_path, auth_header_env=auth_header_env, active=active
    )


def _require_evidence(report: ScanReport, *, public_requests: object = _UNSET) -> None:
    _require_completion(report)
    if public_requests is not _UNSET and (
        not isinstance(public_requests, int)
        or isinstance(public_requests, bool)
        or public_requests < 1
    ):
        raise RuntimeError("public_route_not_tested")
    if not any(
        finding.engine == "zap"
        and finding.rule_id == "ZAP/10021"
        and finding.http_method == "GET"
        and finding.http_path == "/public"
        for finding in report.findings
    ):
        public_seed = any(
            item.engine == "zap"
            and item.kind == "dast"
            and "GET /public" in getattr(item, "eligible_endpoints", ())
            for item in report.executions
        )
        public_alert = any(
            finding.engine == "zap"
            and finding.http_method == "GET"
            and finding.http_path == "/public"
            for finding in report.findings
        )
        rule_ids = sorted(
            {
                finding.rule_id
                for finding in report.findings
                if finding.engine == "zap" and re.fullmatch(r"ZAP/[0-9]{1,6}", finding.rule_id)
            }
        )[:16]
        print(
            "DAST alert diagnostic: "
            f"public_seed={int(public_seed)} public_alert={int(public_alert)} "
            f"rule_ids={','.join(rule_ids) if rule_ids else 'none'}",
            file=sys.stderr,
        )
        raise RuntimeError("expected_alert_missing")
    if any(
        finding.file_path is not None
        or finding.http_method != "GET"
        or finding.http_path not in {"/public", "/protected", "/sql-vulnerable", "/sql-safe"}
        for finding in report.findings
    ):
        raise RuntimeError("dast_scope_violation")


def _require_active_evidence(
    report: ScanReport, *, before: dict[str, object], after: dict[str, object]
) -> None:
    """Require a completed active scan and a distinct positive/control pair."""

    _require_completion(report)
    active_executions = [
        item
        for item in report.executions
        if item.engine == "zap"
        and item.kind == "dast"
        and item.status == "completed"
        and "openapi-active" in item.checks
    ]
    expected = {"GET /sql-vulnerable", "GET /sql-safe"}
    if not active_executions or not any(
        set(item.eligible_endpoints) == expected for item in active_executions
    ):
        raise RuntimeError("active_execution_missing")
    if any(
        finding.file_path is not None
        or finding.http_method != "GET"
        or finding.http_path not in {"/sql-vulnerable", "/sql-safe"}
        for finding in report.findings
    ):
        raise RuntimeError("dast_scope_violation")
    if any(
        finding.engine == "zap"
        and finding.rule_id == "ZAP/40018"
        and finding.http_path == "/sql-safe"
        for finding in report.findings
    ):
        raise RuntimeError("active_safe_control_alert")
    if not any(
        finding.engine == "zap"
        and finding.rule_id == "ZAP/40018"
        and finding.http_method == "GET"
        and finding.http_path == "/sql-vulnerable"
        and "CWE-89" in finding.cwe_ids
        for finding in report.findings
    ):
        raise RuntimeError("active_sql_alert_missing")
    for key, reason in (
        ("sql_vulnerable_mutations", "active_vulnerable_route_not_attacked"),
        ("sql_safe_mutations", "active_safe_route_not_attacked"),
    ):
        previous = before.get(key)
        current = after.get(key)
        if (
            not isinstance(previous, int)
            or isinstance(previous, bool)
            or not isinstance(current, int)
            or isinstance(current, bool)
            or current <= previous
        ):
            raise RuntimeError(reason)


def _require_completion(report: ScanReport) -> None:
    if any(
        item.engine == "zap" and item.kind == "dast" and item.status == "completed"
        for item in report.executions
    ):
        return
    for item in report.executions:
        if item.engine == "zap" and item.kind == "dast":
            reason = getattr(item, "reason", None)
            if reason in _SAFE_FAILURE_CODES:
                raise RuntimeError(reason)
    raise RuntimeError("dast_incomplete")


def run_evidence(output_dir: Path = _DEFAULT_OUTPUT) -> None:
    """Build, scan and remove one labelled fixture, writing only normalized reports."""

    for name in _ARTIFACT_NAMES:
        (output_dir / name).unlink(missing_ok=True)
    _docker_executable()
    _prepare_zap_image()
    print("DAST stage: image-ready", flush=True)
    project = f"secragraph-dast-{uuid4().hex[:12]}"
    token = secrets.token_urlsafe(32)
    environment = os.environ.copy()
    environment["SECRAGRAPH_DAST_TEST_TOKEN"] = token
    try:
        started = _run_compose(
            project,
            ["up", "--build", "--detach", "--wait", "--wait-timeout", "240"],
            environment,
            600,
        )
        if started.returncode != 0:
            raise RuntimeError("fixture_start_failed")
        container = _fixture_container(project, environment)
        if _fetch_fixture_json(container, "/health").get("status") != "ok":
            raise RuntimeError("fixture_unhealthy")
        print("DAST stage: fixture-ready", flush=True)

        previous_header = os.environ.get("ZAP_AUTH_HEADER_VALUE")
        os.environ["ZAP_AUTH_HEADER_VALUE"] = f"Session {token}"
        try:
            report = _scan(
                container,
                8000,
                "/openapi.json",
                auth_header_env="ZAP_AUTH_HEADER_VALUE",
                active=False,
            )
            print("DAST stage: passive-returned", flush=True)
            before_active = _fetch_fixture_json(container, "/stats")
            active_report = _scan(
                container,
                8000,
                "/openapi.json",
                auth_header_env="ZAP_AUTH_HEADER_VALUE",
                active=True,
            )
            print("DAST stage: active-returned", flush=True)
        finally:
            if previous_header is None:
                os.environ.pop("ZAP_AUTH_HEADER_VALUE", None)
            else:
                os.environ["ZAP_AUTH_HEADER_VALUE"] = previous_header

        after_active = _fetch_fixture_json(container, "/stats")
        _require_evidence(report, public_requests=before_active.get("public_requests"))
        count = before_active.get("authenticated_protected_requests")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuntimeError("authenticated_route_not_tested")
        _require_active_evidence(active_report, before=before_active, after=after_active)
        _assert_host_redirect_isolated(container)
        print("DAST stage: evidence-checked", flush=True)

        rendered = {
            "dast.json": render_report(report, ReportFormat.JSON),
            "dast.md": render_report(report, ReportFormat.MARKDOWN),
            "dast.sarif": render_report(report, ReportFormat.SARIF),
            "dast-active.json": render_report(active_report, ReportFormat.JSON),
            "dast-active.md": render_report(active_report, ReportFormat.MARKDOWN),
            "dast-active.sarif": render_report(active_report, ReportFormat.SARIF),
        }
        if any(token in content or f"Session {token}" in content for content in rendered.values()):
            raise RuntimeError("credential_in_report")
    finally:
        stopped = _run_compose(
            project,
            ["down", "--volumes", "--remove-orphans", "--timeout", "20"],
            environment,
            120,
        )
        if stopped.returncode != 0:
            raise RuntimeError("fixture_cleanup_failed")
    print("DAST stage: cleanup-complete", flush=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in rendered.items():
        (output_dir / name).write_text(content, encoding="utf-8")


def _safe_failure_location(error: BaseException) -> str:
    """Expose fixed source file names and line numbers, never exception values."""

    allowed = {
        "run_dast_evidence.py",
        "runner.py",
        "zap.py",
        "tempfile.py",
        "shutil.py",
        "pathlib.py",
        "contextlib.py",
    }
    frames: list[str] = []
    traceback = error.__traceback__
    while traceback is not None:
        name = Path(traceback.tb_frame.f_code.co_filename).name
        if name in allowed:
            frames.append(f"{name}:{traceback.tb_lineno}")
        traceback = traceback.tb_next
    return ">".join(frames[-4:])


def main() -> int:
    try:
        run_evidence()
    except Exception as error:  # Never print raw subprocess errors or a disposable credential.
        code = (
            str(error)
            if type(error) is RuntimeError and str(error) in _SAFE_FAILURE_CODES
            else f"unknown:{type(error).__name__}"
        )
        location = _safe_failure_location(error) if code.startswith("unknown:") else ""
        suffix = f" at {location}" if location else ""
        print(f"DAST evidence generation failed ({code}{suffix}).", file=sys.stderr)
        return 1
    print("DAST evidence passed: isolated fixture and normalized reports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
