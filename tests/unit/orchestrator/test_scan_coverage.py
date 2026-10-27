from pathlib import Path

from security_review.domain.models import ScanExecution, ScanStatus
from security_review.intelligence.dependency_osv import DependencyAuditResult
from security_review.orchestrator.scan_graph import (
    PROCESSING_TIME_LIMIT_EXCEEDED,
    DeterministicScanResult,
    ScanGraphServices,
    ScanRequest,
    build_scan_graph,
)
from security_review.scanner.files import ScanLimits


def test_graph_preserves_engine_coverage_and_incomplete_status() -> None:
    execution = ScanExecution(
        engine="semgrep",
        kind="sast",
        status="not_run",
        elapsed_ms=0,
        eligible_files=("app.py",),
        reason="tool_unavailable",
    )

    def scan(request: ScanRequest) -> DeterministicScanResult:
        return DeterministicScanResult(
            target_name=request.target.name,
            findings=(),
            executions=(execution,),
        )

    result = build_scan_graph(ScanGraphServices(deterministic_scanner=scan)).invoke(
        {"target": Path("app.py"), "limits": ScanLimits()}
    )
    report = result["report"]
    assert report.executions == (execution,)
    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS


def test_graph_adds_osv_lockfile_coverage() -> None:
    def audit(_target: Path, _limits: ScanLimits) -> DependencyAuditResult:
        return DependencyAuditResult(
            status="not_run",
            warnings=("dependency_osv_unavailable",),
            eligible_files=("uv.lock",),
            elapsed_ms=12,
        )

    result = build_scan_graph(
        ScanGraphServices(
            deterministic_scanner=lambda request: DeterministicScanResult(
                target_name=request.target.name, findings=()
            ),
            dependency_auditor=audit,
        )
    ).invoke({"target": Path("uv.lock"), "limits": ScanLimits()})
    report = result["report"]
    assert len(report.executions) == 1
    assert report.executions[0].engine == "osv"
    assert report.executions[0].kind == "dependency"
    assert report.executions[0].status == "not_run"
    assert report.executions[0].eligible_files == ("uv.lock",)
    assert report.status is ScanStatus.COMPLETED_WITH_WARNINGS


def test_graph_records_osv_not_run_when_scan_deadline_is_exhausted() -> None:
    def unexpected_audit(_target: Path, _limits: ScanLimits) -> DependencyAuditResult:
        raise AssertionError("OSV must not run after the deadline")

    result = build_scan_graph(
        ScanGraphServices(
            deterministic_scanner=lambda request: DeterministicScanResult(
                target_name=request.target.name,
                findings=(),
                warnings=(PROCESSING_TIME_LIMIT_EXCEEDED,),
            ),
            dependency_auditor=unexpected_audit,
        )
    ).invoke({"target": Path("uv.lock"), "limits": ScanLimits()})

    report = result["report"]
    assert len(report.executions) == 1
    assert report.executions[0].engine == "osv"
    assert report.executions[0].status == "not_run"
    assert report.executions[0].reason == "scan_deadline_exceeded"
    assert report.executions[0].eligible_files == ("uv.lock",)
