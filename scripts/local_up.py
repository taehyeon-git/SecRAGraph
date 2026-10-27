"""Start the complete local SecRAGraph workflow from one command."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from security_review.intelligence.ingestion import _has_link_like_component
from security_review.membership.service import (
    MembershipError,
    MembershipService,
    normalize_username,
)
from security_review.storage.intelligence import (
    CVE_TABLE,
    CWE_TABLE,
    IntelligenceImportError,
    import_intelligence_data,
)
from security_review.storage.members import SqlAlchemyMembershipRepository
from security_review.storage.models import MemberRow

_ROOT = Path(__file__).resolve().parents[1]


class StartupError(Exception):
    """A bounded, user-safe startup failure."""


@dataclass(frozen=True, repr=False)
class RuntimeSecrets:
    path: Path
    admin_password: str
    reader_password: str
    settings: Mapping[str, str] = field(default_factory=dict)


class PreparedCorpus(Protocol):
    @property
    def root(self) -> Path: ...

    @property
    def manifest_path(self) -> Path: ...

    @property
    def coverage_path(self) -> Path: ...

    @property
    def status(self) -> str: ...

    @property
    def document_count(self) -> int: ...


_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")
_MAX_RUNTIME_ENV_BYTES = 1_024
_PORT_DEFAULTS = {"POSTGRES_PORT": 5432, "QDRANT_PORT": 6333, "API_PORT": 8000, "WEB_PORT": 8501}
_SAFE_RUNTIME_SETTINGS = {
    **{name: str(value) for name, value in _PORT_DEFAULTS.items()},
    "SECRAGRAPH_QDRANT_VECTOR_DIMENSION": "1536",
    "SECRAGRAPH_QDRANT_COLLECTION": "secragraph-auto-cwe",
    "SECRAGRAPH_AUTO_OSV_ENABLED": "false",
    "SECRAGRAPH_AUTO_CWE_ENABLED": "false",
    "SECRAGRAPH_OPENAI_API_KEY": "",
}


def _docker_executable() -> str | None:
    return shutil.which("docker")


def _check_docker(docker: str) -> None:
    _checked_run(
        [docker, "info", "--format", "{{.ServerVersion}}"],
        stage="Docker daemon check",
        cwd=_ROOT,
        env=os.environ.copy(),
        timeout=30,
    )
    _checked_run(
        [docker, "compose", "version"],
        stage="Docker Compose check",
        cwd=_ROOT,
        env=os.environ.copy(),
        timeout=30,
    )


def _volume_exists(docker: str) -> bool:
    completed = _checked_run(
        [
            docker,
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
        ],
        stage="Docker volume inspection",
        cwd=_ROOT,
        env=os.environ.copy(),
        timeout=30,
        capture_stdout=True,
    )
    return "secragraph_postgres_data" in completed.stdout.splitlines()


def _checked_run(
    command: list[str],
    *,
    stage: str,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
    capture_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded child process without echoing or retaining secret-bearing logs."""

    try:
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=cwd,
            env=dict(env),
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,  # nosec B603
        )
    except (OSError, subprocess.TimeoutExpired):
        raise StartupError(
            f"{stage} did not complete. Check the local services and retry."
        ) from None
    if completed.returncode != 0:
        raise StartupError(f"{stage} failed. Check the local services and retry.")
    return completed


def _compose_environment(runtime: RuntimeSecrets, base: Mapping[str, str]) -> dict[str, str]:
    environment = {**_SAFE_RUNTIME_SETTINGS, **runtime.settings, **base}
    environment.update(
        {
            "POSTGRES_USER": "secragraph",
            "POSTGRES_DB": "secragraph",
            "POSTGRES_PASSWORD": runtime.admin_password,
            "SECRAGRAPH_READER_PASSWORD": runtime.reader_password,
            "SECRAGRAPH_ENVIRONMENT": "production",
            "SECRAGRAPH_QDRANT_COLLECTION": "secragraph-auto-cwe",
        }
    )
    environment.pop("SECRAGRAPH_API_TOKEN", None)
    return environment


def _start_compose(
    docker: str,
    runtime: RuntimeSecrets,
    environment: Mapping[str, str],
    repo_root: Path,
    offline: bool = False,
) -> None:
    prefix = [docker, "compose", "-p", "secragraph", "--env-file", str(runtime.path)]
    _checked_run(
        [*prefix, "config", "--quiet"],
        stage="Docker Compose configuration",
        cwd=repo_root,
        env=environment,
        timeout=30,
    )
    image_policy = ["--build", "--pull", "never"] if offline else ["--build"]
    _checked_run(
        [*prefix, "up", *image_policy, "--detach", "--wait", "--wait-timeout", "240"],
        stage=(
            "Offline Docker Compose startup (local build cache required)"
            if offline
            else "Docker Compose startup"
        ),
        cwd=repo_root,
        env=environment,
        timeout=900,
    )
    tool_check = (
        "import shutil, sys; "
        "required = ('opengrep', 'gitleaks', 'checkov'); "
        "sys.exit(0 if all(shutil.which(name) for name in required) else 2)"
    )
    _checked_run(
        [*prefix, "exec", "-T", "api", "/app/.venv/bin/python", "-c", tool_check],
        stage="Scanner tool availability",
        cwd=repo_root,
        env=environment,
        timeout=30,
    )


def _stop_api_web(
    docker: str, runtime: RuntimeSecrets, environment: Mapping[str, str], repo_root: Path
) -> None:
    """Stop only frontends; PostgreSQL, Qdrant, and their volumes remain intact."""

    _checked_run(
        [
            docker,
            "compose",
            "-p",
            "secragraph",
            "--env-file",
            str(runtime.path),
            "stop",
            "web",
            "api",
        ],
        stage="API/web stop",
        cwd=repo_root,
        env=environment,
        timeout=90,
    )


def _recreate_api_web(
    docker: str, runtime: RuntimeSecrets, environment: Mapping[str, str], repo_root: Path
) -> None:
    """Recreate frontends only after the verified corpus is fully synchronized."""

    _checked_run(
        [
            docker,
            "compose",
            "-p",
            "secragraph",
            "--env-file",
            str(runtime.path),
            "up",
            "--no-deps",
            "--no-build",
            "--force-recreate",
            "--detach",
            "--wait",
            "--wait-timeout",
            "240",
            "api",
            "web",
        ],
        stage="API/web activation",
        cwd=repo_root,
        env=environment,
        timeout=360,
    )


def _secure_api_web_after_failure(
    docker: str, runtime: RuntimeSecrets, keyless: Mapping[str, str], repo_root: Path
) -> str:
    """Prefer stopping frontends; if stop fails, force a keyless recreation."""

    try:
        _stop_api_web(docker, runtime, keyless, repo_root)
        return "API/web stopped; data volumes retained."
    except Exception:
        try:
            _recreate_api_web(docker, runtime, keyless, repo_root)
            return "API/web restarted without a provider key; data volumes retained."
        except Exception:
            raise StartupError(
                "Could not secure API/web after corpus failure. Stop both services manually."
            ) from None


def _prepare_corpus(repo_root: Path, *, offline: bool) -> PreparedCorpus:
    """Collect the case-matched sources and reject an invalid generated manifest."""

    try:
        from security_review.intelligence.case_corpus import prepare_case_corpus
        from security_review.intelligence.manifest import load_verified_corpus

        result = prepare_case_corpus(
            repo_root, repo_root / "build" / "auto-corpus", offline=offline
        )
        if result.status not in {"official", "cached", "fallback"}:
            raise ValueError("unexpected corpus status")
        if result.document_count < 1:
            raise ValueError("empty corpus")
        load_verified_corpus(result.root, result.manifest_path)
        return result
    except Exception:
        raise StartupError("Unable to prepare a verified case corpus.") from None


def _run_evaluations(repo_root: Path) -> None:
    """Publish fixed-guide RAG evidence before starting the stack."""

    output_dir = repo_root / "build" / "evidence"
    temporary = repo_root / "build" / "local" / "tmp"
    temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        temporary.chmod(0o700)
    environment = os.environ.copy()
    environment.update({name: str(temporary) for name in ("TMPDIR", "TEMP", "TMP")})
    _checked_run(
        [sys.executable, "-m", "scripts.run_rag_evidence", "--output-dir", str(output_dir)],
        stage="Fixed-guide offline RAG evaluation",
        cwd=repo_root,
        env=environment,
        timeout=180,
    )


def _port(environment: Mapping[str, str], name: str, default: int) -> int:
    value = environment.get(name, str(default))
    try:
        port = int(value)
    except ValueError:
        raise StartupError(f"Invalid {name} port.") from None
    if port < 1 or port > 65535:
        raise StartupError(f"Invalid {name} port.")
    return port


def _vector_dimension(environment: Mapping[str, str]) -> str:
    value = environment.get("SECRAGRAPH_QDRANT_VECTOR_DIMENSION", "1536")
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise StartupError("Invalid Qdrant vector dimension.")
    return str(int(value))


def _database_engine(runtime: RuntimeSecrets, environment: Mapping[str, str]) -> Engine:
    database_url = URL.create(
        "postgresql+psycopg",
        username="secragraph",
        password=runtime.admin_password,
        host="127.0.0.1",
        port=_port(environment, "POSTGRES_PORT", 5432),
        database="secragraph",
    )
    return create_engine(database_url, pool_pre_ping=True, connect_args={"connect_timeout": 5})


def _seed_synthetic_samples(
    runtime: RuntimeSecrets, environment: Mapping[str, str], repo_root: Path
) -> None:
    """Seed a fresh knowledge DB, never overwrite any existing intelligence."""

    engine = _database_engine(runtime, environment)
    try:
        with engine.connect() as connection:
            existing_cwe = connection.scalar(select(func.count()).select_from(CWE_TABLE)) or 0
            existing_cve = connection.scalar(select(func.count()).select_from(CVE_TABLE)) or 0
        if existing_cwe or existing_cve:
            print("Existing Text2SQL knowledge retained; synthetic sample import skipped.")
            return
        summary = import_intelligence_data(
            engine, repo_root / "data/samples/cwe.csv", repo_root / "data/samples/cve.csv"
        )
        print(
            f"Imported {summary.cwe_rows} synthetic CWE and {summary.cve_rows} synthetic CVE rows."
        )
    except (SQLAlchemyError, IntelligenceImportError, OSError):
        raise StartupError("Synthetic Text2SQL sample initialization failed.") from None
    finally:
        engine.dispose()


def _prompt_initial_member() -> tuple[str, str]:
    if not sys.stdin.isatty():
        raise StartupError("The first member must be created from an interactive terminal.")
    try:
        username = normalize_username(input("Initial member username [admin]: ") or "admin")
        password = getpass.getpass("Initial member password: ")
        confirmation = getpass.getpass("Confirm member password: ")
    except (EOFError, KeyboardInterrupt):
        raise StartupError("Initial member setup was interrupted; rerun startup.") from None
    except MembershipError:
        raise StartupError(
            "Invalid initial member username (3–32 printable ASCII characters)."
        ) from None
    if password != confirmation:
        raise StartupError("Member passwords did not match; rerun startup.")
    try:
        password_length = len(password.encode("utf-8"))
    except UnicodeEncodeError:
        password_length = 0
    if not 12 <= password_length <= 1024:
        raise StartupError("Member password must be 12–1024 UTF-8 bytes.")
    return username, password


def _ensure_first_member(runtime: RuntimeSecrets, environment: Mapping[str, str]) -> None:
    """Create the first account only if migration left the member table empty."""

    engine = _database_engine(runtime, environment)
    try:
        with Session(engine) as session:
            member_count = session.scalar(select(func.count()).select_from(MemberRow)) or 0
        if member_count:
            print("Existing member account retained.")
            return
        username, password = _prompt_initial_member()
        factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
        MembershipService(SqlAlchemyMembershipRepository(factory)).register(username, password)
        print("Initial member account created.")
    except (SQLAlchemyError, MembershipError, ValueError):
        raise StartupError(
            "Initial member setup failed; rerun startup after checking PostgreSQL."
        ) from None
    finally:
        engine.dispose()


def _probe_url(url: str) -> None:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=5) as response:
            if response.status != 200:
                raise StartupError("A local service health check failed.")
    except (OSError, urllib.error.URLError):
        raise StartupError("A local service health check failed.") from None


def _check_health(environment: Mapping[str, str]) -> None:
    api_port = _port(environment, "API_PORT", 8000)
    web_port = _port(environment, "WEB_PORT", 8501)
    _probe_url(f"http://127.0.0.1:{api_port}/health/ready")
    _probe_url(f"http://127.0.0.1:{web_port}/_stcore/health")


def _apply_corpus(corpus: PreparedCorpus, environment: Mapping[str, str], repo_root: Path) -> None:
    """Apply only the collector's verified manifest to local Qdrant."""

    apply_environment = dict(environment)
    qdrant_port = _port(environment, "QDRANT_PORT", 6333)
    apply_environment["SECRAGRAPH_QDRANT_URL"] = f"http://127.0.0.1:{qdrant_port}"
    receipt = repo_root / "build" / "evidence" / "ingest-receipt.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    _checked_run(
        [
            sys.executable,
            "-m",
            "security_review.cli",
            "sync-corpus",
            str(corpus.root),
            "--manifest",
            str(corpus.manifest_path),
            "--apply",
            "--receipt",
            str(receipt),
        ],
        stage="Verified corpus indexing",
        cwd=repo_root,
        env=apply_environment,
        timeout=900,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Start SecRAGraph's local evaluation and app stack"
    )
    parser.add_argument(
        "--offline", action="store_true", help="use verified cache or project-authored fallback"
    )
    args = parser.parse_args(argv)
    docker = _docker_executable()
    if docker is None:
        print(
            "Docker is unavailable; install Docker Desktop or Docker Engine first.", file=sys.stderr
        )
        return 2
    try:
        _check_docker(docker)
        runtime = _load_or_create_runtime_env(_ROOT, docker)
        environment = _compose_environment(runtime, os.environ)
        corpus = _prepare_corpus(_ROOT, offline=args.offline)
        if args.offline:
            environment["SECRAGRAPH_AUTO_OSV_ENABLED"] = "false"
            environment["SECRAGRAPH_AUTO_CWE_ENABLED"] = "false"
            environment["SECRAGRAPH_OPENAI_API_KEY"] = ""
        else:
            environment["SECRAGRAPH_AUTO_OSV_ENABLED"] = os.environ.get(
                "SECRAGRAPH_AUTO_OSV_ENABLED", "true"
            )
            environment["SECRAGRAPH_AUTO_CWE_ENABLED"] = os.environ.get(
                "SECRAGRAPH_AUTO_CWE_ENABLED", "true"
            )
            if corpus.status == "fallback":
                environment["SECRAGRAPH_OPENAI_API_KEY"] = ""
        _run_evaluations(_ROOT)
        _persist_compose_config(runtime, environment)
        provider_requested = bool(
            not args.offline
            and corpus.status in {"official", "cached"}
            and environment.get("SECRAGRAPH_OPENAI_API_KEY", "").strip()
        )
        keyless_environment = (
            {**environment, "SECRAGRAPH_OPENAI_API_KEY": ""} if provider_requested else environment
        )
        if provider_requested:
            _stop_api_web(docker, runtime, keyless_environment, _ROOT)
        _start_compose(docker, runtime, keyless_environment, _ROOT, args.offline)
        _seed_synthetic_samples(runtime, keyless_environment, _ROOT)
        _ensure_first_member(runtime, keyless_environment)
        _check_health(keyless_environment)
        if args.offline:
            print("offline mode: live RAG indexing and automatic OSV lookup disabled.")
        elif corpus.status == "fallback":
            print("live RAG disabled: no verified official CWE cache is available.")
        elif provider_requested:
            try:
                _apply_corpus(corpus, environment, _ROOT)
            except Exception:
                secured = _secure_api_web_after_failure(docker, runtime, keyless_environment, _ROOT)
                raise StartupError(f"Corpus indexing failed; {secured}") from None
            try:
                _recreate_api_web(docker, runtime, environment, _ROOT)
                _check_health(environment)
            except Exception:
                secured = _secure_api_web_after_failure(docker, runtime, keyless_environment, _ROOT)
                raise StartupError(f"Provider activation failed; {secured}") from None
            print(f"RAG corpus indexed: {corpus.status} ({corpus.document_count} documents).")
        else:
            print(
                "RAG indexing unavailable: set SECRAGRAPH_OPENAI_API_KEY. Offline evidence ready."
            )
        if corpus.status == "fallback":
            print(
                "Corpus provenance: project-authored fallback only; no official CWE coverage claim."
            )
        else:
            print(f"Corpus provenance: {corpus.status} ({corpus.document_count} documents).")
        print(f"Case coverage: {corpus.coverage_path}")
        print("Fixed-guide RAG evidence: build/evidence/")
        print(f"API: http://127.0.0.1:{_port(environment, 'API_PORT', 8000)}")
        print(f"Web: http://127.0.0.1:{_port(environment, 'WEB_PORT', 8501)}")
        return 0
    except StartupError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print(
            "Local startup failed; saved data was not removed. Check Docker and retry.",
            file=sys.stderr,
        )
        return 1


def _render_runtime_env(
    admin_password: str, reader_password: str, settings: Mapping[str, str]
) -> str:
    lines = [
        f"POSTGRES_PASSWORD={admin_password}",
        f"SECRAGRAPH_READER_PASSWORD={reader_password}",
        *(f"{name}={settings[name]}" for name in _SAFE_RUNTIME_SETTINGS),
    ]
    return "\n".join(lines) + "\n"


def _load_or_create_runtime_env(repo_root: Path, docker: str) -> RuntimeSecrets:
    path = repo_root / "build" / "local" / "runtime.env"
    if not path.resolve().is_relative_to(repo_root.resolve()) or _has_link_like_component(path):
        raise StartupError("Unsafe runtime.env path.")
    if path.exists():
        return _read_runtime_env(path)
    if _volume_exists(docker):
        raise StartupError(
            "An existing PostgreSQL volume has no saved runtime.env credentials. "
            "Restore its original credentials before startup; data was not modified."
        )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.parent.chmod(0o700)
    admin_password = secrets.token_urlsafe(32)
    reader_password = secrets.token_urlsafe(32)
    content = _render_runtime_env(admin_password, reader_password, _SAFE_RUNTIME_SETTINGS)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _read_runtime_env(path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        path.unlink(missing_ok=True)
        raise StartupError("Unable to persist runtime.env credentials.") from None
    if os.name != "nt":
        path.chmod(0o600)
    return RuntimeSecrets(path, admin_password, reader_password, dict(_SAFE_RUNTIME_SETTINGS))


def _read_runtime_env(path: Path) -> RuntimeSecrets:
    if _has_link_like_component(path) or not path.is_file():
        raise StartupError("Unsafe runtime.env file.")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(_MAX_RUNTIME_ENV_BYTES + 1)
        if len(raw) > _MAX_RUNTIME_ENV_BYTES:
            raise ValueError("oversized runtime state")
        lines = raw.decode("utf-8").splitlines()
        fields: dict[str, str] = {}
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError("missing separator")
            name, value = line.split("=", 1)
            if name not in {
                "POSTGRES_PASSWORD",
                "SECRAGRAPH_READER_PASSWORD",
                *_SAFE_RUNTIME_SETTINGS,
            }:
                raise ValueError("unexpected field")
            if name in fields:
                raise ValueError("repeated field")
            if name in {"POSTGRES_PASSWORD", "SECRAGRAPH_READER_PASSWORD"}:
                if _SECRET_PATTERN.fullmatch(value) is None:
                    raise ValueError("invalid secret")
            elif name in _PORT_DEFAULTS:
                if not value.isdecimal() or not 1 <= int(value) <= 65535:
                    raise ValueError("invalid port")
            elif name == "SECRAGRAPH_QDRANT_VECTOR_DIMENSION":
                if not value.isdecimal() or not 1 <= int(value) <= 65535:
                    raise ValueError("invalid vector dimension")
            elif name == "SECRAGRAPH_QDRANT_COLLECTION":
                if value != "secragraph-auto-cwe":
                    raise ValueError("invalid collection")
            elif name in {"SECRAGRAPH_AUTO_OSV_ENABLED", "SECRAGRAPH_AUTO_CWE_ENABLED"}:
                if value not in {"true", "false"}:
                    raise ValueError("invalid automatic evidence mode")
            elif value != "":
                raise ValueError("provider key must not be saved")
            fields[name] = value
        if (
            "POSTGRES_PASSWORD" not in fields
            or "SECRAGRAPH_READER_PASSWORD" not in fields
            or fields["POSTGRES_PASSWORD"] == fields["SECRAGRAPH_READER_PASSWORD"]
        ):
            raise ValueError("missing or repeated secret")
        if os.name != "nt":
            path.chmod(0o600)
        return RuntimeSecrets(
            path,
            fields["POSTGRES_PASSWORD"],
            fields["SECRAGRAPH_READER_PASSWORD"],
            {
                **_SAFE_RUNTIME_SETTINGS,
                **{name: fields[name] for name in _SAFE_RUNTIME_SETTINGS if name in fields},
            },
        )
    except (OSError, UnicodeError, ValueError, KeyError):
        raise StartupError("Invalid runtime.env credentials; restore the saved file.") from None


def _persist_compose_config(runtime: RuntimeSecrets, environment: Mapping[str, str]) -> None:
    """Atomically persist reproducible Compose settings while keeping provider keys ephemeral."""

    path = runtime.path
    if _has_link_like_component(path) or not path.is_file():
        raise StartupError("Unsafe runtime.env file.")
    mode = environment.get("SECRAGRAPH_AUTO_OSV_ENABLED", "true")
    if mode not in {"true", "false"}:
        raise StartupError("Invalid automatic OSV mode.")
    cwe_mode = environment.get("SECRAGRAPH_AUTO_CWE_ENABLED", "true")
    if cwe_mode not in {"true", "false"}:
        raise StartupError("Invalid automatic CWE mode.")
    settings = {
        **{
            name: str(_port(environment, name, default)) for name, default in _PORT_DEFAULTS.items()
        },
        "SECRAGRAPH_QDRANT_VECTOR_DIMENSION": _vector_dimension(environment),
        "SECRAGRAPH_QDRANT_COLLECTION": "secragraph-auto-cwe",
        "SECRAGRAPH_AUTO_OSV_ENABLED": mode,
        "SECRAGRAPH_AUTO_CWE_ENABLED": cwe_mode,
        "SECRAGRAPH_OPENAI_API_KEY": "",
    }
    content = _render_runtime_env(runtime.admin_password, runtime.reader_password, settings)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".runtime-", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    except OSError:
        raise StartupError("Unable to persist runtime.env Compose settings.") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
