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
