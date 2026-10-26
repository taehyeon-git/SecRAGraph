"""Runtime contracts for the isolated hardened Compose stack."""

from __future__ import annotations

import io
import json
import os
import secrets
import subprocess
import zipfile
from pathlib import Path
from shutil import which

import httpx
import pytest

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


def _compose(*args: str, project: str | None = None) -> subprocess.CompletedProcess[str]:
    docker = which("docker")
    assert docker is not None
    env = os.environ.copy()
    env_file = env.get("SECRAGRAPH_RUNTIME_ENV_FILE")
    if not env_file:
        if not env.get("POSTGRES_PASSWORD"):
            env["POSTGRES_PASSWORD"] = secrets.token_urlsafe(32)
        if not env.get("SECRAGRAPH_READER_PASSWORD"):
            env["SECRAGRAPH_READER_PASSWORD"] = secrets.token_urlsafe(32)
        if not env.get("SECRAGRAPH_API_TOKEN"):
            env["SECRAGRAPH_API_TOKEN"] = secrets.token_urlsafe(32)
    command = [docker, "compose"]
    if env_file:
        command.extend(("--env-file", env_file))
    if project is not None:
        command.extend(("-p", project))
    return subprocess.run(  # noqa: S603
        [*command, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )


def _project() -> str:
    project = os.environ.get("SECRAGRAPH_RUNTIME_TEST_PROJECT")
    if not project:
        pytest.skip("set SECRAGRAPH_RUNTIME_TEST_PROJECT for live container checks")
    return project


def _container_id(project: str, service: str) -> str:
    return _compose("ps", "-q", service, project=project).stdout.strip()


def _inspect(project: str, service: str) -> dict[str, object]:
    docker = which("docker")
    assert docker is not None
    container_id = _container_id(project, service)
    assert container_id, f"{service} is not running in {project}"
    result = subprocess.run(  # noqa: S603
        [docker, "inspect", container_id],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    return json.loads(result.stdout)[0]


def _exec(project: str, service: str, *args: str) -> subprocess.CompletedProcess[str]:
    return _compose("exec", "-T", service, *args, project=project)


def _url(service: str, path: str) -> str:
    port = os.environ.get("API_PORT" if service == "api" else "WEB_PORT")
    assert port, f"{service} host port must be explicit for isolated checks"
    return f"http://127.0.0.1:{port}{path}"


def _api_headers() -> dict[str, str]:
    token = os.environ.get("SECRAGRAPH_API_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
    username = os.environ.get("SECRAGRAPH_TEST_MEMBER_USERNAME")
    password = os.environ.get("SECRAGRAPH_TEST_MEMBER_PASSWORD")
    assert username and password, "member smoke credentials must be configured"
    login = httpx.post(
        _url("api", "/v1/auth/login"),
        json={"username": username, "password": password},
        timeout=10,
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Session {login.json()['token']}"}


def test_api_and_web_compose_runtime_restrictions() -> None:
    services = json.loads(_compose("config", "--format", "json").stdout)["services"]
    for name in ("postgres", "qdrant", "api", "web"):
        assert services[name]["ports"][0]["host_ip"] == "127.0.0.1"
    for name in ("api", "web"):
        service = services[name]
        assert service["read_only"] is True
        assert service["user"] == "10001:10001"
        assert service["environment"]["TMPDIR"] == "/tmp/secragraph"  # noqa: S108
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["mem_limit"]
        assert service["pids_limit"] > 0
        assert any(mount.startswith("/tmp/secragraph:") for mount in service["tmpfs"])  # noqa: S108


def test_web_compose_limits_streamlit_upload_and_message_sizes() -> None:
    web = json.loads(_compose("config", "--format", "json").stdout)["services"]["web"]
    assert "--server.maxUploadSize=5" in web["command"]
    assert "--server.maxMessageSize=8" in web["command"]


def test_runtime_compose_operator_token_stays_out_of_web() -> None:
    services = json.loads(_compose("config", "--format", "json").stdout)["services"]
    assert "SECRAGRAPH_API_TOKEN" in services["api"]["environment"]
    assert "SECRAGRAPH_API_TOKEN" not in services["web"]["environment"]


def test_runtime_request_headers_use_the_configured_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRAGRAPH_API_TOKEN", "synthetic-test-token")

    assert _api_headers() == {"Authorization": "Bearer synthetic-test-token"}


@pytest.mark.parametrize("service", ["api", "web"])
def test_runtime_identity_filesystem_and_health(service: str) -> None:
    project = _project()
    info = _inspect(project, service)
    host = info["HostConfig"]
    assert info["State"]["Health"]["Status"] == "healthy"
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert host["Memory"] > 0
    assert host["PidsLimit"] > 0
    assert "no-new-privileges:true" in host["SecurityOpt"]
    assert _exec(project, service, "id", "-u").stdout.strip() == "10001"
    assert _exec(project, service, "id", "-g").stdout.strip() == "10001"
    probe = (
        "from pathlib import Path; import os; "
        "p=Path('/tmp/secragraph/probe'); p.write_text('ok'); "
        "assert p.read_text() == 'ok'; p.unlink(); "
        "assert os.getenv('TMPDIR') == '/tmp/secragraph'; "
        "q=Path('/app/probe'); "
        "\ntry: q.write_text('bad')\nexcept OSError: pass\n"
        "else: raise AssertionError('root writable')"
    )
    _exec(project, service, "python", "-c", probe)
    path = "/health/ready" if service == "api" else "/_stcore/health"
    assert httpx.get(_url(service, path), timeout=10).status_code == 200


def test_file_and_spooled_multipart_uploads_persist_reports() -> None:
    _project()
    base = _url("api", "/v1/scans/file")
    for source in (b"eval(user_input)\n", b"eval(user_input)\n" + b"# pad\n" * 220_000):
        response = httpx.post(
            base,
            headers=_api_headers(),
            files={"file": ("app.py", source, "text/x-python")},
            timeout=60,
        )
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["target_name"] == "app.py"
        loaded = httpx.get(
            _url("api", f"/v1/scans/{report['scan_id']}"),
            headers=_api_headers(),
            timeout=10,
        )
        assert loaded.status_code == 200
        assert loaded.json()["scan_id"] == report["scan_id"]


def test_zip_upload_extracts_and_persists_report() -> None:
    _project()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("src/app.py", "eval(user_input)\n")
    response = httpx.post(
        _url("api", "/v1/scans/archive"),
        headers=_api_headers(),
        files={"file": ("sample.zip", archive.getvalue(), "application/zip")},
        timeout=30,
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["target_name"] == "sample.zip"
    rendered = httpx.get(
        _url("api", f"/v1/scans/{report['scan_id']}/report"),
        headers=_api_headers(),
        timeout=10,
    )
    assert rendered.status_code == 200
    assert "sample.zip" in rendered.text
