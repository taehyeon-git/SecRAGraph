"""The isolated member benchmark never publishes partial or credential-bearing evidence."""

from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


class _Client:
    def __init__(self, **_kwargs: object) -> None:
        pass

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *_args: object) -> None:
        pass


class _Result:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.has_failures = mismatch
        self.benchmark = SimpleNamespace(
            has_coverage_failures=False,
            has_finding_mismatches=mismatch,
            coverage=SimpleNamespace(scanned=2, total=2),
        )

    def to_json(self) -> str:
        return json.dumps({"transport": "member_session", "scanned": 2}) + "\n"

    def to_markdown(self) -> str:
        return "# Member scanner benchmark\n\n2/2 cases scanned.\n"


def _runner():  # type: ignore[no-untyped-def]
    return importlib.import_module("scripts.run_authenticated_scanner_benchmark")


def _isolated_fakes(
    monkeypatch: pytest.MonkeyPatch,
    runner: object,
    *,
    output_dir: Path,
    fail_cleanup: bool = False,
) -> tuple[list[tuple[str, tuple[str, ...], dict[str, str]]], list[str]]:
    ports = iter((41001, 41002, 41003, 41004))
    monkeypatch.setattr(runner, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(runner, "_reserve_port", lambda: next(ports))
    monkeypatch.setattr(runner.httpx, "Client", _Client)
    compositions: list[tuple[str, tuple[str, ...], dict[str, str]]] = []
    members: list[str] = []

    def fake_compose(
        _docker: str,
        project: str,
        arguments: list[str],
        environment: dict[str, str],
        _timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        compositions.append((project, tuple(arguments), environment.copy()))
        if arguments[0] == "down":
            assert not (output_dir / "member-scanner.json").exists()
        code = 1 if fail_cleanup and arguments[0] == "down" else 0
        return subprocess.CompletedProcess(arguments, code)

    def fake_member(
        _docker: str, _project: str, _environment: dict[str, str], username: str, password: str
    ) -> None:
        assert username and password
        members.append(username)

    monkeypatch.setattr(runner, "_run_compose", fake_compose)
    monkeypatch.setattr(runner, "_create_synthetic_member", fake_member)
    return compositions, members


def test_one_command_runs_two_members_offline_and_publishes_only_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    cases = tmp_path / "cases.json"
    cases.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("SECRAGRAPH_API_TOKEN", "operator-secret-marker")
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "model-secret-marker")
    monkeypatch.setenv("COMPOSE_ENV_FILES", "DONT_USE_OPERATOR_ENV")
    compositions, members = _isolated_fakes(monkeypatch, runner, output_dir=output_dir)
    seen: list[tuple[Path, str, str]] = []

    def fake_evaluate(
        _client: object,
        cases_path: Path,
        *,
        username: str,
        password: str,
        second_username: str,
        second_password: str,
    ) -> _Result:
        assert username != second_username
        assert password != second_password
        seen.append((cases_path, username, second_username))
        return _Result()

    monkeypatch.setattr(runner, "run_authenticated_scanner_benchmark", fake_evaluate)

    assert runner.main(["--cases", str(cases), "--output-dir", str(output_dir)]) == 0
    assert [arguments[0] for _, arguments, _ in compositions] == ["up", "down"]
    assert compositions[0][0] == compositions[1][0]
    assert compositions[0][0].startswith("secragraph-member-bench-")
    assert members == [seen[0][1], seen[0][2]]
    assert seen[0][0] == cases
    for _, _, environment in compositions:
        assert environment["SECRAGRAPH_AUTO_CWE_ENABLED"] == "false"
        assert environment["SECRAGRAPH_AUTO_OSV_ENABLED"] == "false"
        assert environment["SECRAGRAPH_ENVIRONMENT"] == "production"
        assert environment["SECRAGRAPH_API_TOKEN"] == ""
        assert environment["SECRAGRAPH_OPENAI_API_KEY"] == ""
        assert environment["COMPOSE_DISABLE_ENV_FILE"] == "1"
        assert "COMPOSE_ENV_FILES" not in environment
        assert environment["COMPOSE_FILE"].endswith("compose.yaml")
        assert environment["COMPOSE_PROFILES"] == ""
        assert environment["API_PORT"] == "41003"
    assert json.loads((output_dir / "member-scanner.json").read_text(encoding="utf-8")) == {
        "transport": "member_session",
        "scanned": 2,
    }
    assert (
        (output_dir / "member-scanner.md")
        .read_text(encoding="utf-8")
        .startswith("# Member scanner benchmark")
    )
    rendered = (output_dir / "member-scanner.json").read_text(encoding="utf-8")
    rendered += (output_dir / "member-scanner.md").read_text(encoding="utf-8")
    rendered += capsys.readouterr().out
    assert "operator-secret-marker" not in rendered
    assert "model-secret-marker" not in rendered
    assert all(member not in rendered for member in members)


def test_request_failure_cleans_stack_and_leaves_no_new_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    compositions, _ = _isolated_fakes(monkeypatch, runner, output_dir=output_dir)

    def fail(*_args: object, **_kwargs: object) -> _Result:
        raise RuntimeError("session-token-private-marker")

    monkeypatch.setattr(runner, "run_authenticated_scanner_benchmark", fail)
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert [arguments[0] for _, arguments, _ in compositions] == ["up", "down"]
    assert not output_dir.exists()
    output = capsys.readouterr()
    assert "session-token-private-marker" not in output.out + output.err


def test_safe_core_failure_code_is_visible_without_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    _isolated_fakes(monkeypatch, runner, output_dir=output_dir)

    def fail(*_args: object, **_kwargs: object) -> _Result:
        raise runner.AuthenticatedBenchmarkError("member_login_failed")

    monkeypatch.setattr(runner, "run_authenticated_scanner_benchmark", fail)
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert "member_login_failed" in capsys.readouterr().err
    assert not output_dir.exists()


def test_cleanup_failure_does_not_publish_success_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    _isolated_fakes(monkeypatch, runner, output_dir=output_dir, fail_cleanup=True)
    monkeypatch.setattr(
        runner, "run_authenticated_scanner_benchmark", lambda *_args, **_kwargs: _Result()
    )
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert not output_dir.exists()


def test_completed_scans_with_finding_mismatch_write_diagnostics_but_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    _isolated_fakes(monkeypatch, runner, output_dir=output_dir)
    monkeypatch.setattr(
        runner,
        "run_authenticated_scanner_benchmark",
        lambda *_args, **_kwargs: _Result(mismatch=True),
    )
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert (output_dir / "member-scanner.json").exists()


def test_completed_scans_with_auth_failure_write_diagnostics_but_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    _isolated_fakes(monkeypatch, runner, output_dir=output_dir)
    result = _Result()
    result.has_failures = True
    monkeypatch.setattr(
        runner, "run_authenticated_scanner_benchmark", lambda *_args, **_kwargs: result
    )
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert (output_dir / "member-scanner.json").exists()


def test_unsafe_serialized_report_is_not_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    _isolated_fakes(monkeypatch, runner, output_dir=output_dir)
    result = _Result()
    monkeypatch.setattr(
        result, "to_json", lambda: '{"scan_id":"12345678-1234-1234-1234-123456789abc"}'
    )
    monkeypatch.setattr(
        runner, "run_authenticated_scanner_benchmark", lambda *_args, **_kwargs: result
    )
    assert runner.main(["--output-dir", str(output_dir)]) == 1
    assert not output_dir.exists()


def test_missing_docker_stops_before_any_member_or_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    monkeypatch.setattr(runner, "_docker_executable", lambda: None)
    assert runner.main(["--output-dir", str(tmp_path / "evidence")]) == 2
    assert not (tmp_path / "evidence").exists()


def test_failed_rerun_removes_previous_success_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    output_dir = tmp_path / "evidence"
    output_dir.mkdir()
    (output_dir / "member-scanner.json").write_text("old passing evidence", encoding="utf-8")
    (output_dir / "member-scanner.md").write_text("old passing evidence", encoding="utf-8")
    monkeypatch.setattr(runner, "_docker_executable", lambda: None)

    assert runner.main(["--output-dir", str(output_dir)]) == 2
    assert not (output_dir / "member-scanner.json").exists()
    assert not (output_dir / "member-scanner.md").exists()


def test_publication_failure_leaves_no_half_written_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner()
    original_replace = Path.replace

    def fail_second_replace(self: Path, target: Path) -> Path:
        if self.name == "member-scanner.md":
            raise OSError("publication failure")
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", fail_second_replace)
    with pytest.raises(OSError, match="publication failure"):
        runner._write_evidence(tmp_path, "{}\n", "# report\n")

    assert not (tmp_path / "member-scanner.json").exists()
    assert not (tmp_path / "member-scanner.md").exists()
