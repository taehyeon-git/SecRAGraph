"""Evaluate scanner cases through two real member sessions in isolated Compose."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import httpx

from scripts.compose_smoke import (
    _create_synthetic_member,
    _docker_executable,
    _reserve_port,
    _run_compose,
)
from security_review.evaluation.authenticated_scanner import (
    AuthenticatedBenchmarkError,
    AuthenticatedScannerResult,
    run_authenticated_scanner_benchmark,
)

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CASES = _ROOT / "data" / "evaluation" / "scanner_cases.json"
_DEFAULT_OUTPUT = _ROOT / "build" / "evidence"
_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _distinct_loopback_ports() -> tuple[int, int, int, int]:
    selected: set[int] = set()
    for _attempt in range(16):
        selected.add(_reserve_port())
        if len(selected) == 4:
            break
    if len(selected) != 4:
        raise OSError("unable_to_reserve_ports")
    postgres, qdrant, api, web = sorted(selected)
    return postgres, qdrant, api, web


def _isolated_environment(ports: tuple[int, int, int, int]) -> dict[str, str]:
    postgres, qdrant, api, web = ports
    # Override even when the developer's Compose .env contains provider credentials.
    empty_value = ""
    environment = os.environ.copy()
    environment.update(
        {
            "POSTGRES_DB": f"secragraph_{secrets.token_hex(8)}",
            "POSTGRES_USER": "secragraph",
            "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_READER_PASSWORD": secrets.token_urlsafe(32),
            "SECRAGRAPH_ENVIRONMENT": "production",
            "SECRAGRAPH_AUTO_CWE_ENABLED": "false",
            "SECRAGRAPH_AUTO_OSV_ENABLED": "false",
            "SECRAGRAPH_API_TOKEN": empty_value,
            "SECRAGRAPH_OPENAI_API_KEY": empty_value,
            "COMPOSE_DISABLE_ENV_FILE": "1",
            "COMPOSE_FILE": str(_ROOT / "compose.yaml"),
            "COMPOSE_PROFILES": "",
            "POSTGRES_PORT": str(postgres),
            "QDRANT_PORT": str(qdrant),
            "API_PORT": str(api),
            "WEB_PORT": str(web),
        }
    )
    environment.pop("COMPOSE_ENV_FILES", None)
    return environment


def _safe_evidence(
    result: AuthenticatedScannerResult, secrets_to_check: tuple[str, ...]
) -> tuple[str, str]:
    json_text = result.to_json()
    markdown_text = result.to_markdown()
    for rendered in (json_text, markdown_text):
        if not isinstance(rendered, str) or any(secret in rendered for secret in secrets_to_check):
            raise ValueError("unsafe_evidence")
        if _UUID_PATTERN.search(rendered):
            raise ValueError("unsafe_evidence")
    return json_text, markdown_text


def _write_evidence(output_dir: Path, json_text: str, markdown_text: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".member-scanner-", dir=output_dir) as temporary:
        stage = Path(temporary)
        staged_json = stage / "member-scanner.json"
        staged_markdown = stage / "member-scanner.md"
        staged_json.write_text(json_text, encoding="utf-8", newline="\n")
        staged_markdown.write_text(markdown_text, encoding="utf-8", newline="\n")
        try:
            staged_json.replace(output_dir / staged_json.name)
            staged_markdown.replace(output_dir / staged_markdown.name)
        except OSError:
            _remove_generated_evidence(output_dir)
            raise


def _remove_generated_evidence(output_dir: Path) -> None:
    """Remove only this command's public artifact names, including stale results."""

    for name in ("member-scanner.json", "member-scanner.md"):
        (output_dir / name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=_DEFAULT_CASES)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT)
    arguments = parser.parse_args(argv)

    try:
        _remove_generated_evidence(arguments.output_dir)
    except OSError:
        print("Previous authenticated benchmark evidence could not be cleared.", file=sys.stderr)
        return 1

    docker = _docker_executable()
    if docker is None:
        print("Docker is unavailable for the authenticated benchmark.", file=sys.stderr)
        return 2
    try:
        ports = _distinct_loopback_ports()
    except OSError:
        print("Unable to allocate isolated loopback ports.", file=sys.stderr)
        return 2

    project = f"secragraph-member-bench-{uuid4().hex[:12]}"
    environment = _isolated_environment(ports)
    username = f"bench-{secrets.token_hex(8)}"
    password = secrets.token_urlsafe(32)
    second_username = f"bench-other-{secrets.token_hex(8)}"
    second_password = secrets.token_urlsafe(32)
    result: AuthenticatedScannerResult | None = None
    failed = False
    cleanup_ok = False
    try:
        started = _run_compose(
            docker,
            project,
            ["up", "--build", "--detach", "--wait", "--wait-timeout", "240"],
            environment,
            600,
        )
        if started.returncode != 0:
            raise ValueError("compose_start_failed")
        _create_synthetic_member(docker, project, environment, username, password)
        _create_synthetic_member(docker, project, environment, second_username, second_password)
        with httpx.Client(
            base_url=f"http://127.0.0.1:{ports[2]}",
            timeout=30,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            result = run_authenticated_scanner_benchmark(
                client,
                arguments.cases,
                username=username,
                password=password,
                second_username=second_username,
                second_password=second_password,
            )
    except AuthenticatedBenchmarkError as error:
        failed = True
        code = str(error)
        if re.fullmatch(r"[a-z][a-z0-9_]*", code):
            print(f"Authenticated benchmark failed: {code}.", file=sys.stderr)
        else:
            print("Authenticated benchmark failed before all checks completed.", file=sys.stderr)
    except Exception:
        failed = True
        print("Authenticated benchmark failed before all checks completed.", file=sys.stderr)
    finally:
        try:
            stopped = _run_compose(
                docker,
                project,
                ["down", "--volumes", "--remove-orphans", "--timeout", "20"],
                environment,
                120,
            )
            cleanup_ok = stopped.returncode == 0
        except Exception:
            cleanup_ok = False
        if not cleanup_ok:
            print("Isolated Compose cleanup failed.", file=sys.stderr)

    if failed or not cleanup_ok or result is None:
        return 1
    try:
        json_text, markdown_text = _safe_evidence(
            result,
            (username, password, second_username, second_password),
        )
        _write_evidence(arguments.output_dir, json_text, markdown_text)
    except Exception:
        print("Authenticated benchmark evidence could not be published.", file=sys.stderr)
        return 1

    benchmark = result.benchmark
    if result.has_failures:
        print("Authenticated benchmark completed with diagnostic failures.", file=sys.stderr)
        return 1
    scanned = benchmark.coverage.scanned
    total = benchmark.coverage.total
    print(f"Authenticated benchmark passed: {scanned}/{total} cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
