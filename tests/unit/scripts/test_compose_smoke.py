from __future__ import annotations

import subprocess

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
