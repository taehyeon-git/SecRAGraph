from pathlib import Path
from time import monotonic

import pytest

from security_review import application
from security_review.application import _deterministic_scan, _execution_record
from security_review.domain.models import Confidence, Finding, Severity
from security_review.orchestrator.scan_graph import ScanRequest
from security_review.scanner.external_common import ExternalExecution, ExternalScanResult
from security_review.scanner.files import ScanLimits, discover_files


class FakeAdapter:
    def __init__(self, scanner: str, status: str, findings: tuple[Finding, ...] = ()) -> None:
        self.scanner = scanner
        self.status = status
        self.findings = findings
        self.calls: list[Path] = []

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        assert timeout > 0
        self.calls.append(root)
        return ExternalScanResult(
            findings=self.findings,
            execution=ExternalExecution(
                scanner=self.scanner,
                version="1.0",
                status=self.status,  # type: ignore[arg-type]
                eligible_files=("app.py",),
                inspected_files=("app.py",) if self.status == "completed" else (),
                duration_ms=5,
                warnings=("tool_unavailable",) if self.status == "not_run" else (),
            ),
        )


def test_multiengine_pipeline_preserves_findings_and_incomplete_coverage(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = input()\n", encoding="utf-8")
    finding = Finding(
        id="OG/test:123",
        rule_id="OG/test",
        category="sast",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=1,
        message="Potential code issue",
        redacted_evidence="[source omitted]",
        confidence=Confidence.MEDIUM,
        remediation="Review the flow.",
        engine="opengrep",
    )
    sast = FakeAdapter("opengrep", "completed", (finding,))
    secrets = FakeAdapter("gitleaks", "not_run")
    config = FakeAdapter("checkov", "skipped")
    request = ScanRequest(target=tmp_path, limits=ScanLimits(), clock=monotonic)

    result = _deterministic_scan(
        request, sast_adapter=sast, secret_adapter=secrets, config_adapter=config
    )

    assert result.findings == (finding,)
    assert [item.engine for item in result.executions] == ["opengrep", "gitleaks", "checkov"]
    assert result.executions[0].languages == ("python",)
    assert result.executions[1].status == "not_run"
    assert result.executions[1].reason == "tool_unavailable"
    assert all(adapter.calls for adapter in (sast, secrets, config))


def test_deadline_coverage_uses_each_engine_supported_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    (tmp_path / ".env.local").write_text("DEMO=true\n", encoding="utf-8")
    discovered = discover_files(tmp_path, ScanLimits())
    monkeypatch.setattr(application, "discover_files", lambda *_a, **_kw: discovered)
    request = ScanRequest(target=tmp_path, limits=ScanLimits(), deadline=1.0, clock=lambda: 2.0)

    result = _deterministic_scan(request)

    by_engine = {execution.engine: execution for execution in result.executions}
    assert by_engine["opengrep"].eligible_files == ("app.py",)
    assert by_engine["gitleaks"].eligible_files == (".env.local", "app.py", "main.tf")
    assert by_engine["checkov"].eligible_files == ("main.tf",)
    assert all(execution.status == "not_run" for execution in result.executions)


def test_coverage_languages_include_extensionless_and_compound_formats() -> None:
    execution = _execution_record(
        ExternalExecution(
            scanner="checkov",
            version=None,
            status="completed",
            eligible_files=("Dockerfile", "infra/main.tf.json", ".env.local"),
        )
    )

    assert execution.languages == ("dockerfile", "dotenv", "terraform")
