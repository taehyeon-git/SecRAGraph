from __future__ import annotations

import subprocess
from uuid import uuid4

import pytest

from scripts import compose_smoke


def test_failed_compose_start_still_cleans_exact_isolated_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []
    ports = iter((41001, 41002, 41003, 41004))
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker", raising=False)
    monkeypatch.setattr(compose_smoke, "_reserve_port", lambda: next(ports), raising=False)

    def fake_compose(
        _docker: str,
        project: str,
        arguments: list[str],
        _environment: dict[str, str],
        _timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((project, tuple(arguments)))
        return subprocess.CompletedProcess(arguments, 1 if arguments[0] == "up" else 0)

    monkeypatch.setattr(compose_smoke, "_run_compose", fake_compose)

    assert compose_smoke.main() == 1
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert calls[0][0] == calls[1][0]
    assert calls[0][0].startswith("secragraph-smoke-")
    assert "--volumes" in calls[1][1]


def test_smoke_provisions_member_and_does_not_configure_operator_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    environments: list[dict[str, str]] = []

    def fake_compose(_docker, _project, arguments, environment, _timeout):
        environments.append(environment.copy())
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(compose_smoke, "_run_compose", fake_compose)
    monkeypatch.setattr(compose_smoke, "_smoke_endpoints", lambda *_args: None)
    monkeypatch.setattr(compose_smoke, "_create_synthetic_member", lambda *_args: None)

    assert compose_smoke.main() == 0
    assert all("SECRAGRAPH_API_TOKEN" not in env for env in environments)


def test_smoke_reports_safe_failure_code_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    monkeypatch.setattr(
        compose_smoke,
        "_run_compose",
        lambda _docker, _project, arguments, _env, _timeout: subprocess.CompletedProcess(
            arguments, 0
        ),
    )
    monkeypatch.setattr(compose_smoke, "_create_synthetic_member", lambda *_args: None)

    def fail_endpoints(*_args: object) -> None:
        raise ValueError("synthetic_finding_missing")

    monkeypatch.setattr(compose_smoke, "_smoke_endpoints", fail_endpoints)
    assert compose_smoke.main() == 1
    assert "synthetic_finding_missing" in capsys.readouterr().err


def test_smoke_suppresses_untrusted_exception_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    monkeypatch.setattr(
        compose_smoke,
        "_run_compose",
        lambda _docker, _project, arguments, _env, _timeout: subprocess.CompletedProcess(
            arguments, 0
        ),
    )

    def fail_member(*_args: object) -> None:
        raise ValueError("synthetic secret marker")

    monkeypatch.setattr(compose_smoke, "_create_synthetic_member", fail_member)
    assert compose_smoke.main() == 1
    output = capsys.readouterr().err
    assert "member_exception" in output
    assert "synthetic secret marker" not in output


def test_synthetic_scan_has_cold_start_timeout_without_post_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_calls: list[dict[str, object]] = []

    class Response:
        def __init__(self, status_code: int, payload: dict[str, object] | None = None):
            self.status_code = status_code
            self._payload = payload or {}
            self.text = ""

        def json(self) -> dict[str, object]:
            return self._payload

    class Client:
        def __init__(self, **_kwargs: object):
            pass

        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def get(self, url: str, **kwargs: object) -> Response:
            if "/v1/scans/" in url and "headers" not in kwargs:
                return Response(401)
            return Response(200)

        def post(self, url: str, **kwargs: object) -> Response:
            if url.endswith("/v1/auth/login"):
                return Response(200, {"token": "test-session"})
            scan_calls.append(kwargs)
            return Response(
                200,
                {
                    "scan_id": str(uuid4()),
                    "findings": [{"engine": "opengrep", "rule_id": "OG/test"}],
                    "executions": [
                        {
                            "engine": "opengrep",
                            "status": "completed",
                            "scanned_files": ["synthetic.py"],
                        }
                    ],
                },
            )

    monkeypatch.setattr(compose_smoke.httpx, "Client", Client)
    compose_smoke._smoke_endpoints(41001, 41002, "member", "password")
    assert len(scan_calls) == 1
    assert scan_calls[0]["timeout"] == 120
