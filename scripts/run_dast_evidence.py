"""Run one passive DAST scan against an isolated disposable API fixture."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from uuid import uuid4

from security_review.domain.models import ScanReport
from security_review.reporting.types import ReportFormat, render_report

_ROOT = Path(__file__).resolve().parents[1]
_COMPOSE_FILE = _ROOT / "infra" / "dast" / "compose.yaml"
_DEFAULT_OUTPUT = _ROOT / "build" / "evidence"
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}\Z")
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


def _scan(container: str, port: int, openapi_path: str, *, auth_header_env: str) -> ScanReport:
    from security_review.dast.application import scan_dast_container

    return scan_dast_container(container, port, openapi_path, auth_header_env=auth_header_env)


def _require_evidence(report: ScanReport) -> None:
    if not any(
        item.engine == "zap" and item.kind == "dast" and item.status == "completed"
        for item in report.executions
    ):
        raise RuntimeError("dast_incomplete")
    if not any(
        finding.engine == "zap"
        and finding.rule_id == "ZAP/10021"
        and finding.http_method == "GET"
        and finding.http_path == "/public"
        for finding in report.findings
    ):
        raise RuntimeError("expected_alert_missing")
    if any(
        finding.file_path is not None
        or finding.http_method != "GET"
        or finding.http_path not in {"/public", "/protected"}
        for finding in report.findings
    ):
        raise RuntimeError("dast_scope_violation")


def run_evidence(output_dir: Path = _DEFAULT_OUTPUT) -> None:
    """Build, scan and remove one labelled fixture, writing only normalized reports."""

    _docker_executable()
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

        previous_header = os.environ.get("ZAP_AUTH_HEADER_VALUE")
        os.environ["ZAP_AUTH_HEADER_VALUE"] = f"Session {token}"
        try:
            report = _scan(
                container, 8000, "/openapi.json", auth_header_env="ZAP_AUTH_HEADER_VALUE"
            )
        finally:
            if previous_header is None:
                os.environ.pop("ZAP_AUTH_HEADER_VALUE", None)
            else:
                os.environ["ZAP_AUTH_HEADER_VALUE"] = previous_header

        _require_evidence(report)
        count = _fetch_fixture_json(container, "/stats").get("authenticated_protected_requests")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuntimeError("authenticated_route_not_tested")

        rendered = {
            "dast.json": render_report(report, ReportFormat.JSON),
            "dast.md": render_report(report, ReportFormat.MARKDOWN),
            "dast.sarif": render_report(report, ReportFormat.SARIF),
        }
        if any(token in content or f"Session {token}" in content for content in rendered.values()):
            raise RuntimeError("credential_in_report")
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, content in rendered.items():
            (output_dir / name).write_text(content, encoding="utf-8")
    finally:
        stopped = _run_compose(
            project,
            ["down", "--volumes", "--remove-orphans", "--timeout", "20"],
            environment,
            120,
        )
        if stopped.returncode != 0:
            raise RuntimeError("fixture_cleanup_failed")


def main() -> int:
    try:
        run_evidence()
    except Exception:  # Never print a subprocess error or a disposable credential.
        print("DAST evidence generation failed.", file=sys.stderr)
        return 1
    print("DAST evidence passed: isolated fixture and normalized reports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
