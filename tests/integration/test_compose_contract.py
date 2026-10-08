"""Default Compose image contracts for the local stack."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from pathlib import Path
from shutil import which

import pytest
from dotenv import dotenv_values
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.integration


def _compose_config(
    *, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    project_root = Path(__file__).resolve().parents[2]
    docker = which("docker")
    assert docker is not None
    values = os.environ.copy() if environment is None else environment.copy()
    if not values.get("POSTGRES_PASSWORD"):
        values["POSTGRES_PASSWORD"] = secrets.token_urlsafe(32)
    if not values.get("SECRAGRAPH_READER_PASSWORD"):
        values["SECRAGRAPH_READER_PASSWORD"] = secrets.token_urlsafe(32)
    # The executable is resolved from PATH; every argument is fixed by this test.
    return subprocess.run(  # noqa: S603
        [docker, "compose", "config", "--format", "json"],
        cwd=project_root,
        env=values,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


@pytest.mark.parametrize("service", ["postgres", "reader-bootstrap"])
def test_default_postgres_images_use_reviewed_major_minor_patch_tag(service: str) -> None:
    result = _compose_config()
    configuration = json.loads(result.stdout)

    assert configuration["services"][service]["image"] == "postgres:16.15-alpine"


def test_default_api_container_selects_json_logging_environment() -> None:
    environment = os.environ.copy()
    environment.pop("SECRAGRAPH_ENVIRONMENT", None)
    result = _compose_config(environment=environment)
    configuration = json.loads(result.stdout)

    assert configuration["services"]["api"]["environment"]["SECRAGRAPH_ENVIRONMENT"] == (
        "production"
    )


def test_default_stack_requires_runtime_database_secrets() -> None:
    project_root = Path(__file__).resolve().parents[2]
    docker = which("docker")
    assert docker is not None
    environment = os.environ.copy()
    environment["POSTGRES_PASSWORD"] = ""
    environment["SECRAGRAPH_READER_PASSWORD"] = ""

    result = subprocess.run(  # noqa: S603
        [docker, "compose", "config", "--format", "json"],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode != 0
    assert "POSTGRES_PASSWORD" in result.stderr or "SECRAGRAPH_READER_PASSWORD" in result.stderr


def test_default_stack_passes_runtime_secrets_to_database_consumers() -> None:
    admin_secret = secrets.token_urlsafe(32)
    reader_secret = secrets.token_urlsafe(32)
    environment = os.environ.copy()
    environment["POSTGRES_PASSWORD"] = admin_secret
    environment["SECRAGRAPH_READER_PASSWORD"] = reader_secret

    result = _compose_config(environment=environment)
    services = json.loads(result.stdout)["services"]

    if not secrets.compare_digest(
        services["postgres"]["environment"]["POSTGRES_PASSWORD"], admin_secret
    ):
        pytest.fail("PostgreSQL did not receive the runtime administrator secret")
    if not secrets.compare_digest(
        services["reader-bootstrap"]["environment"]["SECRAGRAPH_READER_PASSWORD"],
        reader_secret,
    ):
        pytest.fail("reader bootstrap did not receive the runtime reader secret")
    if not secrets.compare_digest(
        services["reader-bootstrap"]["environment"]["PGPASSWORD"], admin_secret
    ):
        pytest.fail("reader bootstrap did not receive the runtime administrator secret")
    for service in ("migrate", "api"):
        database_url = make_url(services[service]["environment"]["SECRAGRAPH_DATABASE_URL"])
        if not database_url.password or not secrets.compare_digest(
            database_url.password, admin_secret
        ):
            pytest.fail(f"{service} did not receive the runtime administrator secret")
    intelligence_url = make_url(
        services["api"]["environment"]["SECRAGRAPH_INTELLIGENCE_DATABASE_URL"]
    )
    if not intelligence_url.password or not secrets.compare_digest(
        intelligence_url.password, reader_secret
    ):
        pytest.fail("API did not receive the runtime reader secret")


def test_sample_env_has_no_usable_database_password() -> None:
    values = dotenv_values(Path(__file__).resolve().parents[2] / ".env.example")
    assert values.get("POSTGRES_PASSWORD") in (None, "")
    assert values.get("SECRAGRAPH_READER_PASSWORD") in (None, "")


def test_integration_database_has_no_password_credentials() -> None:
    project_root = Path(__file__).resolve().parents[2]
    docker = which("docker")
    assert docker is not None
    result = subprocess.run(  # noqa: S603
        [docker, "compose", "-f", "tests/compose.integration.yaml", "config", "--format", "json"],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    postgres = json.loads(result.stdout)["services"]["postgres"]

    assert postgres["environment"]["POSTGRES_HOST_AUTH_METHOD"] == "trust"
    assert "POSTGRES_PASSWORD" not in postgres["environment"]
    assert "SECRAGRAPH_READER_PASSWORD" not in postgres["environment"]
    assert postgres["ports"][0]["host_ip"] == "127.0.0.1"
