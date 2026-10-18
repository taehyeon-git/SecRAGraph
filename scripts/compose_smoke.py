"""Isolated local Compose smoke gate for the API and demo UI."""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess  # nosec B404
import sys
from pathlib import Path
from uuid import UUID, uuid4

import httpx

_ROOT = Path(__file__).resolve().parents[1]


def _docker_executable() -> str | None:
    return shutil.which("docker")


def _reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run_compose(
    docker: str,
    project: str,
    arguments: list[str],
    environment: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [docker, "compose", "-p", project, *arguments],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,  # nosec B603
    )


def _smoke_endpoints(api_port: int, web_port: int, token: str) -> None:
    api = f"http://127.0.0.1:{api_port}"
    web = f"http://127.0.0.1:{web_port}"
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        if client.get(f"{api}/health/ready").status_code != 200:
            raise ValueError("api_not_ready")
        if client.get(f"{web}/_stcore/health").status_code != 200:
            raise ValueError("web_not_ready")
        upload = client.post(
            f"{api}/v1/scans/file",
            headers=headers,
            files={
                "file": (
                    "synthetic.py",
                    b"eval(user_input) # synthetic-canary-not-secret\n",
                    "text/x-python",
                )
            },
        )
        if upload.status_code != 200 or "synthetic-canary-not-secret" in upload.text:
            raise ValueError("synthetic_scan_failed")
        payload = upload.json()
        scan_id = str(UUID(payload["scan_id"]))
        if not any(finding.get("rule_id") == "PY001" for finding in payload["findings"]):
            raise ValueError("synthetic_finding_missing")
        if client.get(f"{api}/v1/scans/{scan_id}", headers=headers).status_code != 200:
            raise ValueError("synthetic_report_unavailable")
        if client.get(f"{api}/v1/scans/{scan_id}").status_code != 401:
            raise ValueError("api_auth_gate_missing")


def main() -> int:
    docker = _docker_executable()
    if docker is None:
        print("Docker is unavailable for the Compose smoke gate.", file=sys.stderr)
        return 2
    project = f"secragraph-smoke-{uuid4().hex[:12]}"
    try:
        selected_ports: set[int] = set()
        for _attempt in range(16):
            selected_ports.add(_reserve_port())
            if len(selected_ports) == 4:
                break
        if len(selected_ports) != 4:
            raise OSError("unable to reserve four distinct ports")
        postgres_port, qdrant_port, api_port, web_port = sorted(selected_ports)
    except OSError:
        print("Unable to allocate isolated loopback ports.", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    environment = os.environ.copy()
    environment.update(
        {
            "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_READER_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_API_TOKEN": token,
            "SECRAGRAPH_ENVIRONMENT": "production",
            "POSTGRES_PORT": str(postgres_port),
            "QDRANT_PORT": str(qdrant_port),
            "API_PORT": str(api_port),
            "WEB_PORT": str(web_port),
        }
    )
    environment.pop("SECRAGRAPH_OPENAI_API_KEY", None)
    status = 1
    try:
        started = _run_compose(
            docker,
            project,
            ["up", "--build", "--detach", "--wait", "--wait-timeout", "240"],
            environment,
            600,
        )
        if started.returncode != 0:
            print("Isolated Compose stack did not become healthy.", file=sys.stderr)
        else:
            _smoke_endpoints(api_port, web_port, token)
            print("Compose smoke passed: API, web, authentication, and synthetic scan.")
            status = 0
    except (OSError, subprocess.TimeoutExpired, httpx.HTTPError, ValueError, KeyError, TypeError):
        print("Compose smoke failed before all checks completed.", file=sys.stderr)
    finally:
        try:
            stopped = _run_compose(
                docker,
                project,
                ["down", "--volumes", "--remove-orphans", "--timeout", "20"],
                environment,
                120,
            )
            if stopped.returncode != 0:
                print("Isolated Compose cleanup failed.", file=sys.stderr)
                status = 1
        except (OSError, subprocess.TimeoutExpired):
            print("Isolated Compose cleanup failed.", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
