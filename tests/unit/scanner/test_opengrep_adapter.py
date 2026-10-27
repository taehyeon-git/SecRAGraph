import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from security_review.scanner import opengrep_adapter
from security_review.scanner.opengrep_adapter import OpengrepAdapter, _normalize_report


def _source(tmp_path: Path) -> Path:
    root = tmp_path / "snapshot"
    root.mkdir()
    (root / "app.py").write_text("value = input()\n", encoding="utf-8")
    return root


def test_missing_binary_is_not_a_clean_scan(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _name: None)

    result = OpengrepAdapter().scan_snapshot(root, timeout=5)

    assert result.findings == ()
    assert result.execution.status == "not_run"
    assert result.execution.eligible_files == ("app.py",)
    assert "tool_unavailable" in result.execution.warnings


def test_missing_taint_rules_are_not_a_clean_scan(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _name: "opengrep")

    result = OpengrepAdapter(taint_rules_root=tmp_path / "missing").scan_snapshot(root, timeout=5)

    assert result.findings == ()
    assert result.execution.status == "not_run"
    assert result.execution.warnings == ("rules_unavailable",)


def test_normalized_result_has_no_source_or_secret_text(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    marker = "SHOULD_NEVER_LEAVE_SCANNER_123456789"
    monkeypatch.setattr("shutil.which", lambda _name: "opengrep")

    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="1.32.0\n")
        assert kwargs["cwd"] == root
        assert "--disable-version-check" in command
        assert "--disable-nosem" in command
        assert "--taint-intrafile" in command
        assert any("secragraph-taint" in str(value) for value in command)
        assert "p/security-audit" not in command
        output = Path(command[command.index("--json-output") + 1])
        output.write_text(
            json.dumps(
                {
                    "version": "1.32.0",
                    "results": [
                        {
                            "check_id": "python.eval.python_eval_rule-eval",
                            "path": "app.py",
                            "start": {"line": 1},
                            "end": {"line": 1},
                            "extra": {
                                "message": marker,
                                "lines": marker,
                                "severity": "ERROR",
                                "metadata": {
                                    "cwe": "CWE-95",
                                    "shortDescription": "Dynamic code execution",
                                },
                            },
                        }
                    ],
                    "errors": [],
                    "paths": {"scanned": ["app.py"], "skipped": []},
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = OpengrepAdapter().scan_snapshot(root, timeout=5)

    assert result.execution.status == "completed"
    assert result.execution.inspected_files == ("app.py",)
    assert result.findings[0].engine == "opengrep"
    assert result.findings[0].cwe_ids == ("CWE-95",)
    assert marker not in str(result)


def test_taint_trace_contains_only_bounded_locations(tmp_path: Path) -> None:
    root = _source(tmp_path)
    marker = "PRIVATE_SOURCE_SNIPPET_DO_NOT_COPY"

    def location(line: int) -> dict[str, object]:
        return {"path": "app.py", "start": {"line": line}, "end": {"line": line}}

    payload = {
        "results": [
            {
                "check_id": "secragraph.python-web-command-taint",
                "path": "app.py",
                "start": {"line": 4},
                "end": {"line": 4},
                "extra": {
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-78"},
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [location(1), marker]],
                        "intermediate_vars": [{"location": location(2), "content": marker}],
                        "taint_sink": ["CliLoc", [location(4), marker]],
                    },
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["app.py"], "skipped": []},
    }

    findings, _, _ = _normalize_report(payload, root, ("app.py",))

    assert [(item.role, item.file_path, item.line_start) for item in findings[0].trace] == [
        ("source", "app.py", 1),
        ("step", "app.py", 2),
        ("sink", "app.py", 4),
    ]
    assert marker not in str(findings)


def test_nonzero_exit_with_results_is_partial(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _name: "opengrep")

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="1.32.0\n")
        output = Path(command[command.index("--json-output") + 1])
        output.write_text(
            json.dumps({"results": [], "errors": [], "paths": {"scanned": ["app.py"]}}),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = OpengrepAdapter().scan_snapshot(root, timeout=5)
    assert result.execution.status != "completed"


def test_report_path_outside_snapshot_is_rejected(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _name: "opengrep")

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        if "--version" in command:
            return SimpleNamespace(returncode=0, stdout="1.32.0\n")
        output = Path(command[command.index("--json-output") + 1])
        output.write_text(
            json.dumps(
                {
                    "results": [{"check_id": "x", "path": "../outside.py", "start": {"line": 1}}],
                    "errors": [],
                    "paths": {"scanned": ["app.py"]},
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = OpengrepAdapter().scan_snapshot(root, timeout=5)
    assert result.findings == ()
    assert result.execution.status == "error"


def test_rule_id_is_bounded_for_database_column(tmp_path: Path) -> None:
    root = _source(tmp_path)
    long_id = "x" * 180
    payload = {
        "results": [
            {
                "check_id": long_id,
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "WARNING", "metadata": {}},
            }
        ],
        "errors": [],
        "paths": {"scanned": ["app.py"], "skipped": []},
    }
    findings, _, _ = _normalize_report(payload, root, ("app.py",))
    assert len(findings[0].rule_id) <= 128
    assert len(findings[0].id) <= 255


def test_version_probe_consumes_opengrep_deadline(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = _source(tmp_path)
    monkeypatch.setattr("shutil.which", lambda _name: "opengrep")
    now = [100.0]
    monkeypatch.setattr(opengrep_adapter, "monotonic", lambda: now[0])

    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        if "--version" in command:
            now[0] = 102.5
            return SimpleNamespace(returncode=0, stdout="1.32.0\n")
        assert float(kwargs["timeout"]) <= 2.5
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = OpengrepAdapter().scan_snapshot(root, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.warnings == ("tool_timeout",)
