from pathlib import Path
from time import monotonic

import pytest

from security_review import application
from security_review.application import _deterministic_scan, _execution_record, scan_path
from security_review.domain.models import Confidence, Finding, ScanReport, Severity
from security_review.orchestrator.scan_graph import ScanRequest
from security_review.scanner.external_common import ExternalExecution, ExternalScanResult
from security_review.scanner.files import ScanLimits, discover_files


class FakeAdapter:
    def __init__(
        self,
        scanner: str,
        status: str,
        findings: tuple[Finding, ...] = (),
        *,
        eligible_files: tuple[str, ...] = ("app.py",),
    ) -> None:
        self.scanner = scanner
        self.status = status
        self.findings = findings
        self.eligible_files = eligible_files
        self.calls: list[Path] = []
        self.timeouts: list[float] = []

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        assert timeout > 0
        self.calls.append(root)
        self.timeouts.append(timeout)
        return ExternalScanResult(
            findings=self.findings,
            execution=ExternalExecution(
                scanner=self.scanner,
                version="1.0",
                status=self.status,  # type: ignore[arg-type]
                eligible_files=self.eligible_files,
                inspected_files=self.eligible_files if self.status == "completed" else (),
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
    compose = FakeAdapter("compose-policy", "skipped", eligible_files=())
    request = ScanRequest(target=tmp_path, limits=ScanLimits(), clock=monotonic)

    result = _deterministic_scan(
        request,
        sast_adapter=sast,
        secret_adapter=secrets,
        config_adapter=config,
        compose_adapter=compose,
    )

    assert result.findings == (finding,)
    assert [item.engine for item in result.executions] == [
        "opengrep",
        "gitleaks",
        "checkov",
        "compose-policy",
    ]
    assert result.executions[0].languages == ("python",)
    assert result.executions[1].status == "not_run"
    assert result.executions[1].reason == "tool_unavailable"
    assert all(adapter.calls for adapter in (sast, secrets, config, compose))


def test_compose_target_has_distinct_configuration_coverage(tmp_path: Path) -> None:
    (tmp_path / "compose.override.yaml").write_text(
        "services:\n  web:\n    privileged: true\n", encoding="utf-8"
    )
    finding = Finding(
        id="COMPOSE-test",
        rule_id="COMPOSE/PRIVILEGED",
        category="configuration",
        severity=Severity.HIGH,
        file_path="compose.override.yaml",
        line_start=3,
        message="A privileged service is declared.",
        redacted_evidence="[REDACTED]",
        confidence=Confidence.HIGH,
        remediation="Remove the privileged setting.",
        engine="compose-policy",
    )
    sast = FakeAdapter("opengrep", "skipped", eligible_files=())
    secrets = FakeAdapter("gitleaks", "completed", eligible_files=("compose.override.yaml",))
    checkov = FakeAdapter("checkov", "skipped", eligible_files=())
    compose = FakeAdapter(
        "compose-policy", "completed", (finding,), eligible_files=("compose.override.yaml",)
    )

    result = _deterministic_scan(
        ScanRequest(target=tmp_path / "compose.override.yaml", limits=ScanLimits()),
        sast_adapter=sast,
        secret_adapter=secrets,
        config_adapter=checkov,
        compose_adapter=compose,
    )

    assert [item.engine for item in result.executions] == [
        "opengrep",
        "gitleaks",
        "checkov",
        "compose-policy",
    ]
    assert result.executions[2].eligible_files == ()
    assert result.executions[2].status == "skipped"
    assert result.executions[3].kind == "configuration"
    assert result.executions[3].eligible_files == ("compose.override.yaml",)
    assert result.executions[3].languages == ("docker-compose",)
    assert result.executions[3].scanned_files == ("compose.override.yaml",)
    assert result.findings == (finding,)
    assert compose.timeouts[0] <= 20.0


def test_compose_finding_survives_langgraph_report_serialization(tmp_path: Path) -> None:
    target = tmp_path / "compose.yaml"
    target.write_text("services:\n  web:\n    privileged: true\n", encoding="utf-8")

    report = scan_path(target, ScanLimits())
    restored = ScanReport.model_validate_json(report.model_dump_json())

    assert [item.engine for item in restored.executions] == [
        "opengrep",
        "gitleaks",
        "checkov",
        "compose-policy",
    ]
    assert restored.executions[2].eligible_files == ()
    assert restored.executions[2].status == "skipped"
    assert restored.executions[3].languages == ("docker-compose",)
    assert restored.executions[3].status == "completed"
    assert [(item.rule_id, item.file_path, item.line_start) for item in restored.findings] == [
        ("COMPOSE/PRIVILEGED", "compose.yaml", 3)
    ]


def test_deadline_coverage_uses_each_engine_supported_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    (tmp_path / "docker-compose.override.yaml").write_text(
        "services:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    (tmp_path / ".env.local").write_text("DEMO=true\n", encoding="utf-8")
    discovered = discover_files(tmp_path, ScanLimits())
    monkeypatch.setattr(application, "discover_files", lambda *_a, **_kw: discovered)
    request = ScanRequest(target=tmp_path, limits=ScanLimits(), deadline=1.0, clock=lambda: 2.0)

    result = _deterministic_scan(request)

    by_engine = {execution.engine: execution for execution in result.executions}
    assert by_engine["opengrep"].eligible_files == ("app.py",)
    assert by_engine["gitleaks"].eligible_files == (
        ".env.local",
        "app.py",
        "docker-compose.override.yaml",
        "main.tf",
    )
    assert by_engine["checkov"].eligible_files == ("main.tf",)
    assert by_engine["compose-policy"].eligible_files == ("docker-compose.override.yaml",)
    assert by_engine["compose-policy"].status == "not_run"
    assert by_engine["compose-policy"].languages == ("docker-compose",)
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
