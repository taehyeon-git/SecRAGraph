"""Contract tests for the dedicated secret and configuration subprocesses."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from security_review.scanner import external_detectors
from security_review.scanner.external_detectors import CheckovAdapter, GitleaksAdapter


def test_external_reports_reject_excess_finding_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(external_detectors, "_MAX_FINDINGS", 1)
    secret = {"RuleID": "generic-api-key", "File": "app.py", "StartLine": 1, "EndLine": 1}
    with pytest.raises(external_detectors._InvalidReport, match="result_limit_exceeded"):
        external_detectors._parse_gitleaks([secret, secret], tmp_path, frozenset({"app.py"}))

    failed = {"check_id": "CKV_AWS_18", "file_path": "/main.tf", "file_line_range": [1, 1]}
    report = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [failed, failed],
            "passed_checks": [],
            "skipped_checks": [],
            "parsing_errors": [],
        },
        "summary": {"parsing_errors": 0, "skipped": 0},
    }
    with pytest.raises(external_detectors._InvalidReport, match="result_limit_exceeded"):
        external_detectors._parse_checkov(
            report, tmp_path, frozenset({"main.tf"}), frozenset({"terraform"})
        )


def test_missing_detectors_are_not_reported_as_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "demo" {}', encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: None)

    for adapter in (GitleaksAdapter(), CheckovAdapter()):
        result = adapter.scan_snapshot(tmp_path, timeout=5)
        assert result.findings == ()
        assert result.execution.status == "not_run"
        assert result.execution.warnings == ("tool_unavailable",)
        assert result.execution.inspected_files == ()


def test_no_eligible_files_skip_without_looking_for_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_lookup(_binary: str) -> None:
        raise AssertionError("tool lookup should not run")

    monkeypatch.setattr(external_detectors.shutil, "which", unexpected_lookup)
    secret_result = GitleaksAdapter().scan_snapshot(tmp_path, timeout=5)
    (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
    config_result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert secret_result.execution.status == "skipped"
    assert config_result.execution.status == "skipped"
    assert secret_result.execution.warnings == ("no_eligible_files",)
    assert config_result.execution.warnings == ("no_eligible_files",)


def test_gitleaks_discards_secret_values_and_uses_trusted_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "CANARY_SECRET_VALUE_2026"
    (tmp_path / "app.py").write_text(f"password = '{canary}'", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("title='hostile'", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "gitleaks")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"gitleaks version 8.30.1\n")
        assert args[0] == "gitleaks" and args[1] == "dir"
        assert "--redact=100" in args
        assert "--ignore-gitleaks-allow" in args
        config_path = Path(args[args.index("--config") + 1])
        assert config_path.parent != tmp_path
        assert "useDefault = true" in config_path.read_text(encoding="utf-8")
        assert kwargs["cwd"] != str(tmp_path)
        assert "GITLEAKS_CONFIG" not in kwargs["env"]
        report_path = Path(args[args.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "File": "app.py",
                        "StartLine": 1,
                        "EndLine": 1,
                        "StartColumn": 12,
                        "Secret": canary,
                        "Match": canary,
                        "Line": canary,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = GitleaksAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "completed"
    assert result.execution.version == "8.30.1"
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "GITLEAKS/generic-api-key"
    assert result.findings[0].engine == "gitleaks"
    assert result.findings[0].category == "secret"
    assert canary not in str(result)
    assert canary not in result.findings[0].model_dump_json()


def test_gitleaks_nonzero_exit_cannot_claim_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("token = 'fixture'", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "gitleaks")

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"8.30.1\n")
        Path(args[args.index("--report-path") + 1]).write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = GitleaksAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status in {"partial", "error"}
    assert result.execution.warnings == ("scanner_failed",)
    assert result.execution.inspected_files == ()


def test_checkov_normalizes_failures_without_returning_source_snippets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "CANARY_CONFIG_SECRET_2026"
    (tmp_path / "main.tf").write_text(
        f'# {canary}\nresource "aws_s3_bucket" "x" {{}}', encoding="utf-8"
    )
    (tmp_path / ".checkov.yaml").write_text(
        "external-checks-git: https://evil.invalid/x", encoding="utf-8"
    )
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")
    monkeypatch.setenv("BC_API_KEY", canary)
    monkeypatch.setenv("GITHUB_TOKEN", canary)
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        assert "--config-file" in args
        trusted_config = Path(args[args.index("--config-file") + 1])
        assert trusted_config.parent != tmp_path
        assert trusted_config.read_text(encoding="utf-8").strip() == "{}"
        assert "--skip-download" in args
        assert "--skip-results-upload" in args
        assert "--download-external-modules" in args
        assert args[args.index("--download-external-modules") + 1] == "false"
        assert "secrets" not in args and "sca_package" not in args
        assert kwargs["cwd"] != str(tmp_path)
        assert "BC_API_KEY" not in kwargs["env"]
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert "LD_LIBRARY_PATH" not in kwargs["env"]
        assert kwargs["env"]["HTTPS_PROXY"] == "http://127.0.0.1:9"
        assert kwargs["env"]["CKV_IGNORE_HIDDEN_DIRECTORIES"] == "false"
        payload = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_18",
                        "file_path": "/main.tf",
                        "file_abs_path": str(tmp_path / "main.tf"),
                        "file_line_range": [2, 2],
                        "resource": "aws_s3_bucket.x",
                        "severity": "HIGH",
                        "code_block": [[2, canary]],
                    }
                ],
                "passed_checks": [],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
        }
        stdout = kwargs["stdout"]
        stdout.write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "completed"
    assert result.execution.version == "3.3.30"
    assert result.execution.checks == ("CKV_AWS_18",)
    assert result.execution.inspected_files == ("main.tf",)
    assert result.findings[0].rule_id == "CHECKOV/CKV_AWS_18"
    assert result.findings[0].engine == "checkov"
    assert result.findings[0].file_path == "main.tf"
    assert canary not in str(result)
    assert canary not in result.findings[0].model_dump_json()


def test_checkov_parse_errors_are_partial_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "broken.tf").write_text("resource ???", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        payload = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [],
                "passed_checks": [],
                "skipped_checks": [],
                "parsing_errors": ["broken.tf"],
            },
            "summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 1},
        }
        kwargs["stdout"].write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "partial"
    assert "parsing_errors" in result.execution.warnings
    assert result.execution.inspected_files == ()


def test_checkov_rejects_result_path_outside_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "main.tf").write_text("resource {}", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        payload = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_18",
                        "file_abs_path": str(tmp_path.parent / "outside.tf"),
                        "file_path": "/main.tf",
                        "file_line_range": [1, 1],
                    }
                ],
                "passed_checks": [],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
        }
        kwargs["stdout"].write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "error"
    assert result.findings == ()
    assert result.execution.inspected_files == ()


def test_checkov_rejects_unrequested_scanner_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "main.tf").write_text("resource {}", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        payload = {
            "check_type": "secrets",
            "results": {
                "failed_checks": [],
                "passed_checks": [],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0},
        }
        kwargs["stdout"].write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "error"
    assert result.execution.warnings == ("unexpected_framework",)


def test_checkov_does_not_claim_file_coverage_without_any_check_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "main.tf").write_text("resource {}", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        payload = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [],
                "passed_checks": [],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0},
        }
        kwargs["stdout"].write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "partial"
    assert "no_file_coverage" in result.execution.warnings
    assert result.execution.inspected_files == ()


def test_checkov_marks_unconfirmed_files_as_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "first.tf").write_text("resource {}", encoding="utf-8")
    (tmp_path / "second.tf").write_text("resource {}", encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda _binary: "checkov")

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        payload = {
            "check_type": "terraform",
            "results": {
                "failed_checks": [],
                "passed_checks": [{"check_id": "CKV_AWS_18", "file_path": "/first.tf"}],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 1, "failed": 0, "skipped": 0, "parsing_errors": 0},
        }
        kwargs["stdout"].write(json.dumps(payload).encode("utf-8"))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)

    result = CheckovAdapter().scan_snapshot(tmp_path, timeout=5)

    assert result.execution.status == "partial"
    assert result.execution.inspected_files == ("first.tf",)
    assert ("second.tf", "not_confirmed_by_tool") in result.execution.skipped


@pytest.mark.parametrize("adapter", [GitleaksAdapter(), CheckovAdapter()])
def test_version_probe_consumes_detector_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    adapter: GitleaksAdapter | CheckovAdapter,
) -> None:
    (tmp_path / "app.py").write_text("value = 1", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}', encoding="utf-8")
    monkeypatch.setattr(external_detectors.shutil, "which", lambda name: name)
    now = [100.0]
    monkeypatch.setattr(external_detectors, "monotonic", lambda: now[0])

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if "--version" in args:
            now[0] = 102.5
            return subprocess.CompletedProcess(args, 0, stdout=b"3.3.30\n")
        assert float(kwargs["timeout"]) <= 2.5
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(external_detectors.subprocess, "run", fake_run)
    result = adapter.scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.warnings == ("scanner_timeout",)
