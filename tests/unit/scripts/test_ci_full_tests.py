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


@pytest.fixture(autouse=True)
def _stub_test_member(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    monkeypatch.setattr(module, "_create_test_member", lambda: ("test-user", "test-pass"))


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


def test_ci_publishes_only_keyless_synthetic_evidence_on_trusted_main_runs() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    quality_steps = workflow["jobs"]["quality"]["steps"]
    uploads = [step for step in quality_steps if "actions/upload-artifact@" in step.get("uses", "")]

    assert len(uploads) == 1
    condition = uploads[0]["if"]
    assert "github.ref == 'refs/heads/main'" in condition
    assert all(
        f"github.event_name == '{event}'" in condition
        for event in ("push", "schedule", "workflow_dispatch")
    )
    assert set(uploads[0]["with"]["path"].splitlines()) == {
        "build/evidence/rag.json",
        "build/evidence/rag.md",
        "build/evidence/multiengine-scanner.json",
        "build/evidence/multiengine-scanner.md",
        "build/evidence/pipeline-contract.json",
        "build/evidence/pipeline-contract.md",
    }
    assert uploads[0]["with"]["if-no-files-found"] == "error"


def test_ci_has_full_stack_compose_smoke_gate() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    smoke = workflow["jobs"]["compose-smoke"]

    assert any("scripts.compose_smoke" in step.get("run", "") for step in smoke["steps"])


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


def test_full_suite_passes_ephemeral_member_credentials_only_to_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("scripts.ci_full_tests")
    _capture_api_process(monkeypatch, module)
    monkeypatch.setattr(module, "wait_for_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_create_test_member", lambda: ("ci-random-user", "ci-random-pass"))
    seen: list[dict[str, str] | None] = []

    def capture_run(_command, *, check, env=None):
        assert check
        seen.append(env)

    monkeypatch.setattr(module, "run", capture_run)
    module.run_full_suite(
        api_command=_sleeping_api_command(), test_command=(sys.executable, "-m", "pytest")
    )

    assert seen[0] is not None
    assert seen[0]["SECRAGRAPH_TEST_MEMBER_USERNAME"] == "ci-random-user"
    assert seen[0]["SECRAGRAPH_TEST_MEMBER_PASSWORD"] == "ci-random-pass"
    assert seen[0]["SECRAGRAPH_TEST_API_URL"] == "http://127.0.0.1:8000"


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
