"""CI's full suite needs a live API with a bounded process lifetime."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]


def _capture_api_process(
    monkeypatch: pytest.MonkeyPatch, module: Any
) -> list[subprocess.Popen[Any]]:
    started: list[subprocess.Popen[Any]] = []
    real_popen = subprocess.Popen

    def start(*args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
        process = real_popen(*args, **kwargs)
        started.append(process)
        return process

    monkeypatch.setattr(module, "Popen", start)
    return started


def _sleeping_api_command() -> tuple[str, ...]:
    return (sys.executable, "-c", "import time; time.sleep(60)")


def test_ci_workflow_bootstraps_qdrant_before_live_api_full_suite() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["tests"]["steps"]
    commands = [step.get("run", "") for step in steps]

    bootstrap = next(i for i, command in enumerate(commands) if "bootstrap-qdrant" in command)
    full_suite = next(i for i, command in enumerate(commands) if "scripts.ci_full_tests" in command)

    assert bootstrap < full_suite
    assert not any("uv run pytest --cov=" in command for command in commands)


def test_full_suite_stops_api_after_tests_succeed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    started = _capture_api_process(monkeypatch, module)
    readiness: list[tuple[str, float]] = []

    def ready(url: str, *, timeout_seconds: float) -> None:
        readiness.append((url, timeout_seconds))

    monkeypatch.setattr(module, "wait_for_url", ready)
    marker = tmp_path / "pytest-ran"
    test_command = (
        sys.executable,
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
        str(marker),
    )

    module.run_full_suite(api_command=_sleeping_api_command(), test_command=test_command)

    assert marker.read_text(encoding="utf-8") == "ran"
    assert readiness == [("http://127.0.0.1:8000/health/ready", 60.0)]
    assert len(started) == 1
    assert started[0].poll() is not None


def test_full_suite_waits_for_selected_local_api(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    started = _capture_api_process(monkeypatch, module)
    readiness: list[tuple[str, float]] = []

    def ready(url: str, *, timeout_seconds: float) -> None:
        readiness.append((url, timeout_seconds))

    monkeypatch.setattr(module, "wait_for_url", ready)

    module.run_full_suite(
        api_command=_sleeping_api_command(),
        test_command=(sys.executable, "-c", "pass"),
        readiness_url="http://127.0.0.1:28081/health/ready",
    )

    assert readiness == [("http://127.0.0.1:28081/health/ready", 60.0)]
    assert len(started) == 1
    assert started[0].poll() is not None


def test_full_suite_stops_api_when_tests_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    started = _capture_api_process(monkeypatch, module)
    monkeypatch.setattr(module, "wait_for_url", lambda *_args, **_kwargs: None)

    with pytest.raises(subprocess.CalledProcessError):
        module.run_full_suite(
            api_command=_sleeping_api_command(),
            test_command=(sys.executable, "-c", "raise SystemExit(7)"),
        )

    assert len(started) == 1
    assert started[0].poll() is not None


def test_full_suite_stops_api_when_readiness_times_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    started = _capture_api_process(monkeypatch, module)
    marker = tmp_path / "pytest-ran"

    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise TimeoutError("API did not become ready")

    monkeypatch.setattr(module, "wait_for_url", unavailable)

    with pytest.raises(TimeoutError, match="API did not become ready"):
        module.run_full_suite(
            api_command=_sleeping_api_command(),
            test_command=(
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
                str(marker),
            ),
        )

    assert not marker.exists()
    assert len(started) == 1
    assert started[0].poll() is not None
