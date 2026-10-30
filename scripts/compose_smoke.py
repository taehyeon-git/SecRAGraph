"""Isolated local Compose smoke gate for the API and demo UI."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess  # nosec B404
import sys
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import httpx

from security_review.reporting.markdown import _escape as _markdown_escape

_ROOT = Path(__file__).resolve().parents[1]
_SYNTHETIC_MARKER = "S3cr3t-" + "X9a2Q7b5R8c1"
_EXPECTED_ENGINES = {
    "opengrep": ("sast", "app.py"),
    "gitleaks": ("secret", "secret.env"),
    "checkov": ("configuration", "bucket.tf"),
    "compose-policy": ("configuration", "compose.yaml"),
}
_EXPECTED_FINDINGS = {
    "opengrep": (frozenset({"OG/python_eval_rule-eval"}), "app.py", 1),
    "gitleaks": (frozenset({"GITLEAKS/generic-api-key"}), "secret.env", 1),
    "checkov": (frozenset({"CHECKOV/CKV_AWS_18", "CHECKOV/CKV2_AWS_62"}), "bucket.tf", 1),
    "compose-policy": (frozenset({"COMPOSE/PRIVILEGED"}), "compose.yaml", 4),
}


def _mixed_archive() -> bytes:
    """Return a stable, inert source/configuration fixture for the API path."""

    samples = (
        ("app.py", b"x = eval(input())\n"),
        ("secret.env", f"MY_API_KEY={_SYNTHETIC_MARKER}\n".encode("ascii")),
        ("compose.yaml", b"services:\n  app:\n    image: example:1\n    privileged: true\n"),
        (
            "bucket.tf",
            b'resource "aws_s3_bucket" "app" {\n  bucket = "synthetic-benchmark-only"\n}\n',
        ),
    )
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        for name, content in samples:
            entry = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, content)
    return output.getvalue()


def _validate_expected_findings(findings: list[dict[str, Any]]) -> None:
    """Require fixture-specific finding identities, locations and source lines."""

    for engine, (rules, file_name, line) in _EXPECTED_FINDINGS.items():
        if not any(
            finding.get("engine") == engine
            and finding.get("rule_id") in rules
            and finding.get("file_path") == file_name
            and type(finding.get("line_start")) is int
            and finding["line_start"] == line
            for finding in findings
        ):
            raise ValueError("synthetic_finding_missing")


def _validate_sarif(sarif: object, findings: list[dict[str, Any]]) -> None:
    """Match every SARIF result to the exact persisted JSON finding and location."""

    try:
        if not isinstance(sarif, dict) or sarif.get("version") != "2.1.0":
            raise ValueError("sarif_report_invalid")
        runs = sarif["runs"]
        if not isinstance(runs, list) or len(runs) != 1:
            raise ValueError("sarif_report_invalid")
        run = runs[0]
        if run["tool"]["driver"]["name"] != "SecRAGraph":
            raise ValueError("sarif_report_invalid")
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        if (
            not isinstance(results, list)
            or len(results) != len(findings)
            or run["invocations"][0]["executionSuccessful"] is not True
        ):
            raise ValueError("sarif_report_invalid")
        expected_rules = {finding["rule_id"] for finding in findings}
        if {rule["id"] for rule in rules} != expected_rules:
            raise ValueError("sarif_report_invalid")
        expected = {
            finding["id"]: (
                finding["rule_id"],
                finding["engine"],
                finding["file_path"],
                finding["line_start"],
            )
            for finding in findings
        }
        if len(expected) != len(findings):
            raise ValueError("sarif_report_invalid")
        observed = {
            result["properties"]["findingId"]: (
                result["ruleId"],
                result["properties"]["engine"],
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                result["locations"][0]["physicalLocation"]["region"]["startLine"],
            )
            for result in results
        }
        if len(observed) != len(results) or observed != expected:
            raise ValueError("sarif_report_invalid")
    except (KeyError, IndexError, TypeError, AttributeError, ValueError) as error:
        raise ValueError("sarif_report_invalid") from error


def _validate_markdown(text: str, scan_id: str, findings: list[dict[str, Any]]) -> None:
    """Match every rendered finding's identity and key fields to persisted JSON."""

    if (
        not text.startswith("# SecRAGraph Security Review\n")
        or f"- Scan ID: {scan_id}\n" not in text
        or f"- Findings: {len(findings)}\n" not in text
        or "\n## Scan coverage\n" not in text
        or "\n## Findings\n" not in text
    ):
        raise ValueError("markdown_report_invalid")
    section = text.split("\n## Findings\n", 1)[1]
    blocks = re.split(r"(?m)^### ", section)
    if len(blocks) - 1 != len(findings):
        raise ValueError("markdown_report_invalid")
    observed: dict[str, set[str]] = {}
    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines or lines[0] in observed:
            raise ValueError("markdown_report_invalid")
        observed[lines[0]] = set(lines[1:])
    try:
        expected_ids = {_markdown_escape(finding["id"]) for finding in findings}
        if len(expected_ids) != len(findings) or set(observed) != expected_ids:
            raise ValueError("markdown_report_invalid")
        for finding in findings:
            lines = observed[_markdown_escape(finding["id"])]
            location = f"{finding['file_path']}:{finding['line_start']}"
            required = {
                f"- Rule: {_markdown_escape(finding['rule_id'])}",
                f"- Engine: {_markdown_escape(finding['engine'])}",
                f"- Location: {_markdown_escape(location)}",
            }
            if not required <= lines:
                raise ValueError("markdown_report_invalid")
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("markdown_report_invalid") from error


_SAFE_FAILURE_CODES = frozenset(
    {
        "synthetic_member_creation_failed",
        "api_not_ready",
        "web_not_ready",
        "synthetic_member_login_failed",
        "synthetic_scan_failed",
        "synthetic_finding_missing",
        "sast_coverage_missing",
        "synthetic_report_unavailable",
        "api_auth_gate_missing",
        "synthetic_secret_leak",
        "persisted_report_mismatch",
        "markdown_report_invalid",
        "sarif_report_invalid",
        "member_isolation_missing",
        "multi_engine_coverage_missing",
    }
)


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


def _create_synthetic_member(
    docker: str, project: str, environment: dict[str, str], username: str, password: str
) -> None:
    """Create an isolated member inside the API image, keeping credentials off argv and logs."""
    code = "\n".join(
        (
            "import json, sys",
            "from security_review.config import Settings",
            "from security_review.membership.service import MembershipService",
            "from security_review.storage.database import create_database_engine",
            "from security_review.storage.database import create_session_factory",
            "from security_review.storage.members import SqlAlchemyMembershipRepository",
            "data = json.load(sys.stdin)",
            "settings = Settings()",
            "engine = create_database_engine(settings.database_url)",
            "factory = create_session_factory(settings.database_url, engine=engine)",
            "MembershipService(SqlAlchemyMembershipRepository(factory)).register(",
            "    data['username'], data['password']",
            ")",
            "engine.dispose()",
        )
    )
    completed = subprocess.run(  # noqa: S603
        [
            docker,
            "compose",
            "-p",
            project,
            "exec",
            "-T",
            "api",
            "/app/.venv/bin/python",
            "-c",
            code,
        ],
        cwd=_ROOT,
        env=environment,
        input=json.dumps({"username": username, "password": password}),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        shell=False,
    )
    if completed.returncode != 0:
        raise ValueError("synthetic_member_creation_failed")


def _smoke_endpoints(
    api_port: int,
    web_port: int,
    username: str,
    password: str,
    other_username: str,
    other_password: str,
) -> dict[str, Any]:
    """Measure one authenticated upload through persistence and every report format."""

    api = f"http://127.0.0.1:{api_port}"
    web = f"http://127.0.0.1:{web_port}"
    stages: dict[str, int] = {}

    def measure(stage: str, operation: Any) -> Any:
        started = monotonic()
        response = operation()
        stages[stage] = max(0, round((monotonic() - started) * 1000))
        return response

    def require_redacted(response: httpx.Response) -> None:
        if _SYNTHETIC_MARKER in response.text:
            raise ValueError("synthetic_secret_leak")

    with httpx.Client(timeout=15, follow_redirects=False) as client:
        if measure("api_ready", lambda: client.get(f"{api}/health/ready")).status_code != 200:
            raise ValueError("api_not_ready")
        if measure("web_ready", lambda: client.get(f"{web}/_stcore/health")).status_code != 200:
            raise ValueError("web_not_ready")
        login = measure(
            "login",
            lambda: client.post(
                f"{api}/v1/auth/login", json={"username": username, "password": password}
            ),
        )
        if login.status_code != 200 or not isinstance(login.json().get("token"), str):
            raise ValueError("synthetic_member_login_failed")
        headers = {"Authorization": f"Session {login.json()['token']}"}
        other_login = client.post(
            f"{api}/v1/auth/login",
            json={"username": other_username, "password": other_password},
        )
        if other_login.status_code != 200 or not isinstance(other_login.json().get("token"), str):
            raise ValueError("synthetic_member_login_failed")
        other_headers = {"Authorization": f"Session {other_login.json()['token']}"}
        fixture = _mixed_archive()
        upload = measure(
            "upload",
            lambda: client.post(
                f"{api}/v1/scans/archive",
                headers=headers,
                timeout=120,  # Scanner cold start can exceed the default timeout.
                files={"file": ("benchmark.zip", fixture, "application/zip")},
            ),
        )
        require_redacted(upload)
        if upload.status_code != 200:
            raise ValueError("synthetic_scan_failed")
        payload = upload.json()
        scan_id = str(UUID(payload["scan_id"]))
        findings = payload.get("findings")
        if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
            raise ValueError("synthetic_finding_missing")
        _validate_expected_findings(findings)
        raw_executions = payload.get("executions")
        if not isinstance(raw_executions, list) or not all(
            isinstance(item, dict) for item in raw_executions
        ):
            raise ValueError("multi_engine_coverage_missing")
        executions = {item.get("engine"): item for item in raw_executions}
        for engine, (kind, file_name) in _EXPECTED_ENGINES.items():
            execution = executions.get(engine)
            if (
                execution is None
                or execution.get("kind") != kind
                or execution.get("status") != "completed"
                or file_name not in execution.get("eligible_files", [])
                or file_name not in execution.get("scanned_files", [])
                or not isinstance(execution.get("elapsed_ms"), int)
            ):
                raise ValueError("multi_engine_coverage_missing")
        report_url = f"{api}/v1/scans/{scan_id}"
        stored = measure("persisted_json", lambda: client.get(report_url, headers=headers))
        require_redacted(stored)
        if stored.status_code != 200:
            raise ValueError("synthetic_report_unavailable")
        if stored.json() != payload:
            raise ValueError("persisted_report_mismatch")
        markdown = measure(
            "markdown",
            lambda: client.get(f"{report_url}/report?format=markdown", headers=headers),
        )
        require_redacted(markdown)
        if markdown.status_code != 200:
            raise ValueError("markdown_report_invalid")
        _validate_markdown(markdown.text, scan_id, findings)
        sarif = measure(
            "sarif",
            lambda: client.get(f"{report_url}/report?format=sarif", headers=headers),
        )
        require_redacted(sarif)
        try:
            sarif_payload = sarif.json()
        except (TypeError, ValueError) as error:
            raise ValueError("sarif_report_invalid") from error
        if sarif.status_code != 200:
            raise ValueError("sarif_report_invalid")
        _validate_sarif(sarif_payload, findings)
        denied_upload = client.post(
            f"{api}/v1/scans/archive",
            files={"file": ("benchmark.zip", fixture, "application/zip")},
        )
        require_redacted(denied_upload)
        if denied_upload.status_code != 401:
            raise ValueError("api_auth_gate_missing")
        if client.get(report_url).status_code != 401:
            raise ValueError("api_auth_gate_missing")
        for url in (
            report_url,
            f"{report_url}/report?format=markdown",
            f"{report_url}/report?format=sarif",
        ):
            denied = client.get(url, headers=other_headers)
            require_redacted(denied)
            if denied.status_code != 404:
                raise ValueError("member_isolation_missing")

    selected_executions = [
        {
            "engine": engine,
            "kind": executions[engine]["kind"],
            "status": executions[engine]["status"],
            "elapsed_ms": executions[engine]["elapsed_ms"],
            "reported_path_semantics": (
                "finding_paths_only" if engine == "gitleaks" else "tool_confirmed_scanned_files"
            ),
            "eligible_files": sorted(
                path
                for path in executions[engine]["eligible_files"]
                if path in _mixed_archive_names()
            ),
            "scanned_files": sorted(
                path
                for path in executions[engine]["scanned_files"]
                if path in _mixed_archive_names()
            ),
            "checks": [
                check
                for check in executions[engine].get("checks", [])
                if isinstance(check, str) and len(check) <= 128 and _SYNTHETIC_MARKER not in check
            ],
        }
        for engine in _EXPECTED_ENGINES
    ]
    return {
        "fixture_sha256": sha256(fixture).hexdigest(),
        "stages_ms": stages,
        "checks": {
            "api_ready": True,
            "web_ready": True,
            "member_login": True,
            "expected_findings": True,
            "engine_coverage": True,
            "persisted_json": True,
            "markdown": True,
            "sarif": True,
            "member_isolation": True,
            "redaction": True,
        },
        "executions": selected_executions,
        "report": {
            "scan_status": payload.get("status"),
            "finding_count": len(findings),
            "warnings_count": len(payload.get("warnings", [])),
        },
    }


def _mixed_archive_names() -> frozenset[str]:
    return frozenset({"app.py", "secret.env", "compose.yaml", "bucket.tf"})


def _source_provenance() -> tuple[str, bool]:
    """Pin evidence to the actual checkout without exposing Git status contents."""

    git = shutil.which("git")
    if git is None:
        raise ValueError("source_provenance_unavailable")
    revision = subprocess.run(  # noqa: S603
        [git, "-C", str(_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
        shell=False,  # nosec B603
    )
    dirty = subprocess.run(  # noqa: S603
        [git, "-C", str(_ROOT), "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
        shell=False,  # nosec B603
    )
    sha = revision.stdout.strip()
    if (
        revision.returncode != 0
        or dirty.returncode != 0
        or re.fullmatch(r"[0-9a-f]{40}", sha) is None
    ):
        raise ValueError("source_provenance_unavailable")
    return sha, bool(dirty.stdout)


def _write_evidence(result: dict[str, Any]) -> None:
    """Write bounded source-free API benchmark files after successful cleanup."""

    target = _ROOT / "build/evidence"
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "pipeline-api.json"
    markdown_path = target / "pipeline-api.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stages = result["stages_ms"]
    lines = [
        "# SecRAGraph authenticated API pipeline benchmark",
        "",
        f"- Source revision: `{result['source_revision']}`",
        f"- Source dirty: `{str(result['source_dirty']).lower()}`",
        f"- Fixture SHA-256: `{result['fixture_sha256']}`",
        f"- Status: `{result['status']}`",
        f"- Findings: {result['report']['finding_count']}",
        "",
        "## Measured stages",
        "",
        "| Stage | Milliseconds |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {stage} | {elapsed} |" for stage, elapsed in stages.items())
    lines.extend(
        [
            "",
            "## Engine execution",
            "",
            "| Engine | Status | Eligible | Reported paths | Path meaning | Milliseconds |",
            "| --- | --- | ---: | ---: | --- | ---: |",
        ]
    )
    lines.extend(
        f"| {item['engine']} | {item['status']} | {len(item['eligible_files'])} | "
        f"{len(item['scanned_files'])} | {item['reported_path_semantics']} | "
        f"{item['elapsed_ms']} |"
        for item in result["executions"]
    )
    lines.extend(["", "## Limits", ""])
    lines.extend(f"- {limit}" for limit in result["limitations"])
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    username = f"smoke-{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(32)
    environment = os.environ.copy()
    environment.update(
        {
            "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_READER_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_ENVIRONMENT": "production",
            "POSTGRES_PORT": str(postgres_port),
            "QDRANT_PORT": str(qdrant_port),
            "API_PORT": str(api_port),
            "WEB_PORT": str(web_port),
            "SECRAGRAPH_AUTO_OSV_ENABLED": "false",
            "SECRAGRAPH_AUTO_CWE_ENABLED": "false",
        }
    )
    environment.pop("SECRAGRAPH_API_TOKEN", None)
    environment.pop("SECRAGRAPH_OPENAI_API_KEY", None)
    status = 1
    stage = "start"
    benchmark: dict[str, Any] | None = None
    startup_ms = 0
    member_setup_ms = 0
    cleanup_ms = 0
    try:
        startup_started = monotonic()
        started = _run_compose(
            docker,
            project,
            ["up", "--build", "--detach", "--wait", "--wait-timeout", "240"],
            environment,
            600,
        )
        startup_ms = max(0, round((monotonic() - startup_started) * 1000))
        if started.returncode != 0:
            print("Isolated Compose stack did not become healthy.", file=sys.stderr)
        else:
            stage = "member"
            member_started = monotonic()
            _create_synthetic_member(docker, project, environment, username, password)
            other_username = f"smoke-{secrets.token_hex(8)}"
            other_password = secrets.token_urlsafe(32)
            _create_synthetic_member(docker, project, environment, other_username, other_password)
            member_setup_ms = max(0, round((monotonic() - member_started) * 1000))
            stage = "endpoints"
            benchmark = _smoke_endpoints(
                api_port, web_port, username, password, other_username, other_password
            )
            print("Compose smoke passed: API, web, authentication, and mixed ZIP scan.")
            status = 0
    except (
        OSError,
        subprocess.TimeoutExpired,
        httpx.HTTPError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        code = (
            str(error)
            if isinstance(error, ValueError) and str(error) in _SAFE_FAILURE_CODES
            else f"{stage}_exception"
        )
        print(f"Compose smoke failed ({code}).", file=sys.stderr)
    finally:
        try:
            cleanup_started = monotonic()
            stopped = _run_compose(
                docker,
                project,
                ["down", "--volumes", "--remove-orphans", "--timeout", "20"],
                environment,
                120,
            )
            cleanup_ms = max(0, round((monotonic() - cleanup_started) * 1000))
            if stopped.returncode != 0:
                print("Isolated Compose cleanup failed.", file=sys.stderr)
                status = 1
        except (OSError, subprocess.TimeoutExpired):
            print("Isolated Compose cleanup failed.", file=sys.stderr)
            status = 1
    if status == 0 and benchmark is not None:
        try:
            revision, source_dirty = _source_provenance()
            benchmark["schema_version"] = 1
            benchmark["source_revision"] = revision
            benchmark["source_dirty"] = source_dirty
            benchmark["status"] = "completed"
            benchmark["stages_ms"].update(
                startup=startup_ms, member_setup=member_setup_ms, cleanup=cleanup_ms
            )
            benchmark["limitations"] = [
                "Authored synthetic ZIP is a regression case, not real-world detection accuracy.",
                "OSV and automatic CWE lookups are disabled; external provider quality "
                "is unmeasured.",
                "No LLM key is configured; live RAG answer quality is unmeasured.",
                "DAST, Git history, and container image scanning run in separate trusted "
                "CI tracks.",
                "Gitleaks reported paths are finding paths, not a file-by-file scan receipt.",
                "Wall times include cold scanner startup and vary by host; no absolute "
                "latency gate applies.",
            ]
            _write_evidence(benchmark)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            print("Unable to write Compose benchmark evidence.", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
