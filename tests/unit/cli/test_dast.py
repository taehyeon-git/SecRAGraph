"""DAST CLI delivers the same normalized report as the application service."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import security_review.cli as cli
from security_review.domain.models import ScanExecution
from security_review.reporting.builder import build_report


def test_dast_command_renders_one_canonical_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = build_report(
        "disposable-api",
        (),
        executions=(ScanExecution(engine="zap", kind="sast", status="completed", elapsed_ms=123),),
    )
    calls: list[tuple[str, int, str, str | None, bool]] = []

    def fake_scan(
        container: str,
        port: int,
        openapi_path: str,
        *,
        auth_header_env: str | None = None,
        active: bool = False,
    ) -> object:
        calls.append((container, port, openapi_path, auth_header_env, active))
        return report

    monkeypatch.setattr(cli, "scan_dast_container", fake_scan)
    output = tmp_path / "dast.json"

    result = CliRunner().invoke(
        cli.app,
        [
            "dast",
            "fixture-container",
            "--port",
            "8080",
            "--openapi-path",
            "/openapi.json",
            "--auth-header-env",
            "TEST_DAST_TOKEN",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("fixture-container", 8080, "/openapi.json", "TEST_DAST_TOKEN", False)]
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_id"] == str(report.scan_id)
    assert payload["executions"][0]["engine"] == "zap"


def test_dast_command_hides_target_error_details(monkeypatch: pytest.MonkeyPatch) -> None:
    def invalid_target(*args: object, **kwargs: object) -> object:
        raise ValueError("hidden-test-token")

    monkeypatch.setattr(cli, "scan_dast_container", invalid_target)
    result = CliRunner().invoke(cli.app, ["dast", "fixture-container"])

    assert result.exit_code == 2
    assert "hidden-test-token" not in result.output


def test_dast_command_explicit_active_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    report = build_report(
        "fixture",
        (),
        executions=(ScanExecution(engine="zap", kind="dast", status="completed", elapsed_ms=1),),
    )
    calls: list[bool] = []

    def fake_scan(*args: object, active: bool = False, **kwargs: object) -> object:
        calls.append(active)
        return report

    monkeypatch.setattr(cli, "scan_dast_container", fake_scan)
    result = CliRunner().invoke(cli.app, ["dast", "a" * 64, "--active"])
    assert result.exit_code == 0, result.output
    assert calls == [True]


def test_dast_command_writes_partial_report_then_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = build_report(
        "disposable-api",
        (),
        ("dast_tool_unavailable",),
        executions=(ScanExecution(engine="zap", kind="sast", status="error", elapsed_ms=0),),
    )
    monkeypatch.setattr(cli, "scan_dast_container", lambda *args, **kwargs: report)
    output = tmp_path / "partial.json"

    result = CliRunner().invoke(
        cli.app,
        ["dast", "fixture-container", "--format", "json", "--output", str(output)],
    )

    assert result.exit_code == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["executions"][0]["status"] == "error"
    assert payload["warnings"] == ["dast_tool_unavailable"]
