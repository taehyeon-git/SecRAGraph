"""Dependency audit results must fail closed without hiding advisory outages."""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from scripts.ci_dependency_audit import classify_audit_result, main


def _report(vulnerabilities: list[dict[str, object]]) -> str:
    return json.dumps(
        {
            "dependencies": [
                {"name": "example", "version": "1.0", "vulns": vulnerabilities},
            ],
            "fixes": [],
        }
    )


def test_network_failure_is_not_reported_as_clean() -> None:
    result = classify_audit_result(returncode=2, stdout="", stderr="connection timeout")
    assert result.status == "audit_unavailable"
    assert result.exit_code == 2


def test_vulnerability_has_distinct_failure_exit() -> None:
    result = classify_audit_result(
        returncode=1,
        stdout=_report([{"id": "PYSEC-2099-1", "fix_versions": ["1.1"]}]),
        stderr="",
    )
    assert result.status == "vulnerabilities_found"
    assert result.exit_code == 1


def test_success_requires_valid_clean_report() -> None:
    result = classify_audit_result(returncode=0, stdout=_report([]), stderr="")
    assert result.status == "clean"
    assert result.exit_code == 0


@pytest.mark.parametrize("stdout", ["", "not json", "{}", '{"dependencies": []}'])
def test_unverifiable_success_is_unavailable(stdout: str) -> None:
    result = classify_audit_result(returncode=0, stdout=stdout, stderr="")
    assert result.status == "audit_unavailable"
    assert result.exit_code == 2


def test_unclassified_tool_failure_is_unavailable() -> None:
    result = classify_audit_result(returncode=1, stdout="", stderr="resolver failed")
    assert result.status == "audit_unavailable"
    assert result.exit_code == 2


def test_cli_runs_strict_json_audit_and_reports_unavailable_without_tool_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: list[str] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        assert kwargs == {"capture_output": True, "text": True, "check": False, "timeout": 120}
        return subprocess.CompletedProcess(command, 2, "", "private diagnostic")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(shutil, "which", lambda _: "/isolated/bin/pip-audit")
    assert main() == 2
    assert observed == [
        "/isolated/bin/pip-audit",
        "--strict",
        "--desc",
        "--format",
        "json",
        "--vulnerability-service",
        "osv",
    ]
    captured = capsys.readouterr()
    assert "audit_unavailable" in captured.err
    assert "private diagnostic" not in captured.out + captured.err


def test_missing_auditor_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert main() == 2
    assert "audit_unavailable" in capsys.readouterr().err
