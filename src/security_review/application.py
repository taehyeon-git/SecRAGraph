"""Shared application service used by the API, CLI, and automation adapters."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from time import monotonic
from typing import Protocol, cast
from uuid import UUID

from security_review.domain.models import Finding, ScanExecution, ScanReport
from security_review.intelligence.dynamic_cwe import CweEvidenceProvider
from security_review.observability import log_scan_completed, request_context_bound
from security_review.orchestrator.scan_graph import (
    DependencyAuditor,
    DeterministicScanResult,
    ScanGraph,
    ScanGraphServices,
    ScanRequest,
    ScanState,
    ScanWorkflowError,
    build_scan_graph,
)
from security_review.ports import ReportRepository
from security_review.scanner.compose_adapter import ComposePolicyAdapter
from security_review.scanner.compose_files import is_compose_file
from security_review.scanner.external_common import ExternalExecution, ExternalScanResult
from security_review.scanner.external_detectors import (
    CheckovAdapter,
    GitleaksAdapter,
    _config_candidate,
)
from security_review.scanner.files import ScanLimits, discover_files
from security_review.scanner.opengrep_adapter import _SOURCE_EXTENSIONS, OpengrepAdapter
from security_review.scanner.python_flow import PythonFlowAdapter
from security_review.scanner.snapshot import safe_snapshot

PROCESSING_TIME_LIMIT_EXCEEDED = "processing_time_limit_exceeded"


class UnsupportedTargetError(ValueError):
    """Raised when an explicit single-file target has no supported source type."""


class _SnapshotAdapter(Protocol):
    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult: ...


_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".dockerfile": "dockerfile",
}
_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")


def _eligible_snapshot_files(scanner: str, paths: tuple[str, ...]) -> tuple[str, ...]:
    if scanner == "gitleaks":
        return paths
    if scanner == "opengrep":
        return tuple(path for path in paths if Path(path).suffix.lower() in _SOURCE_EXTENSIONS)
    if scanner == "python-flow":
        return tuple(path for path in paths if Path(path).suffix.lower() == ".py")
    if scanner == "checkov":
        return tuple(path for path in paths if _config_candidate(path))
    if scanner == "compose-policy":
        return tuple(path for path in paths if is_compose_file(path))
    raise ValueError(f"unknown scanner: {scanner}")


def _language_for_path(path: str) -> str | None:
    if is_compose_file(path):
        return "docker-compose"
    name = Path(path).name.lower()
    if name in {"dockerfile", "containerfile"} or name.startswith(
        ("dockerfile.", "containerfile.")
    ):
        return "dockerfile"
    if name == ".env" or name.startswith(".env."):
        return "dotenv"
    if name.endswith(".tf.json"):
        return "terraform"
    if name in {".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials"}:
        return "text"
    return _LANGUAGE_BY_EXTENSION.get(Path(path).suffix.lower())


def _execution_record(execution: ExternalExecution) -> ScanExecution:
    kind_by_engine = {
        "opengrep": "sast",
        "python-flow": "sast",
        "gitleaks": "secret",
        "checkov": "configuration",
        "compose-policy": "configuration",
    }
    kind = kind_by_engine[execution.scanner]
    reason = next((item for item in execution.warnings if _REASON_CODE.fullmatch(item)), None)
    languages = tuple(
        sorted(
            {
                language
                for path in execution.eligible_files
                if (language := _language_for_path(path)) is not None
            }
        )
    )
    return ScanExecution(
        engine=execution.scanner,
        kind=kind,  # type: ignore[arg-type]
        status=execution.status,
        version=execution.version,
        elapsed_ms=execution.duration_ms,
        eligible_files=execution.eligible_files,
        scanned_files=execution.inspected_files,
        languages=languages,
        checks=execution.checks,
        reason=reason,
    )


def _deterministic_scan(
    request: ScanRequest,
    *,
    sast_adapter: _SnapshotAdapter | None = None,
    flow_adapter: _SnapshotAdapter | None = None,
    secret_adapter: _SnapshotAdapter | None = None,
    config_adapter: _SnapshotAdapter | None = None,
    compose_adapter: _SnapshotAdapter | None = None,
) -> DeterministicScanResult:
    """Scan a bounded, non-executable snapshot with specialized local engines."""

    deadline = request.deadline
    if deadline is None:
        deadline = request.clock() + request.limits.max_processing_seconds
    discovery = discover_files(
        request.target,
        request.limits,
        deadline=deadline,
        clock=request.clock,
    )
    dependency_lock_only = (
        request.target.is_file()
        and request.target.name.lower() == "uv.lock"
        and not discovery.files
        and len(discovery.skipped) == 1
        and discovery.skipped[0].reason == "unsupported_extension"
    )
    if (
        request.target.is_file()
        and not discovery.files
        and len(discovery.skipped) == 1
        and discovery.skipped[0].reason == "unsupported_extension"
        and not dependency_lock_only
    ):
        raise UnsupportedTargetError(f"unsupported_extension: {request.target.name}")

    warnings = list(discovery.warnings)
    warnings.extend(f"{item.path}:{item.reason}" for item in discovery.skipped)
    findings: list[Finding] = []
    executions: list[ScanExecution] = []
    adapters: tuple[tuple[str, _SnapshotAdapter], ...] = (
        ("opengrep", sast_adapter or OpengrepAdapter()),
        ("python-flow", flow_adapter or PythonFlowAdapter()),
        ("gitleaks", secret_adapter or GitleaksAdapter()),
        ("checkov", config_adapter or CheckovAdapter()),
        ("compose-policy", compose_adapter or ComposePolicyAdapter()),
    )
    engine_time_limits = {
        "opengrep": 45.0,
        "python-flow": 10.0,
        "gitleaks": 10.0,
        "checkov": 20.0,
        "compose-policy": 20.0,
    }
    with safe_snapshot(discovery, request.limits) as snapshot:
        warnings.extend(f"{path}:{reason}" for path, reason in snapshot.skipped)
        for scanner, adapter in adapters:
            eligible = _eligible_snapshot_files(scanner, snapshot.paths)
            remaining = max(0.0, deadline - request.clock())
            if remaining <= 0:
                execution = ExternalExecution(
                    scanner=scanner,
                    version=None,
                    status="not_run",
                    eligible_files=eligible,
                    warnings=("scan_deadline_exceeded",),
                )
                result = ExternalScanResult(findings=(), execution=execution)
                if PROCESSING_TIME_LIMIT_EXCEEDED not in warnings:
                    warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
            else:
                try:
                    result = adapter.scan_snapshot(
                        snapshot.root, min(remaining, engine_time_limits[scanner])
                    )
                except Exception:
                    result = ExternalScanResult(
                        findings=(),
                        execution=ExternalExecution(
                            scanner=scanner,
                            version=None,
                            status="error",
                            eligible_files=eligible,
                            warnings=("scanner_failed",),
                        ),
                    )
            if result.execution.scanner != scanner:
                raise ValueError("scanner result identity mismatch")
            findings.extend(result.findings)
            executions.append(_execution_record(result.execution))
            warnings.extend(
                f"{scanner}:{code}"
                for code in result.execution.warnings
                if code != "no_eligible_files"
            )
    return DeterministicScanResult(
        target_name=request.target_name or request.target.name or "scan-target",
        findings=tuple(findings),
        warnings=tuple(warnings),
        executions=tuple(executions),
    )


_DEFAULT_SCAN_GRAPH = build_scan_graph(ScanGraphServices(deterministic_scanner=_deterministic_scan))


def _invoke_scan_graph(
    graph: ScanGraph,
    target: Path,
    limits: ScanLimits,
    *,
    target_name: str | None,
    clock: Callable[[], float],
) -> ScanReport:
    state = cast(
        ScanState,
        graph.invoke(
            {
                "target": target,
                "limits": limits,
                "target_name": target_name,
                "clock": clock,
            }
        ),
    )
    report = state.get("report")
    if not isinstance(report, ScanReport):
        raise ScanWorkflowError("missing_report")
    return report


def scan_path(
    target: Path,
    limits: ScanLimits,
    *,
    target_name: str | None = None,
    clock: Callable[[], float] = monotonic,
    dependency_auditor: DependencyAuditor | None = None,
    cwe_evidence: CweEvidenceProvider | None = None,
) -> ScanReport:
    """Scan one file or directory through the shared LangGraph engine."""

    graph = (
        _DEFAULT_SCAN_GRAPH
        if dependency_auditor is None and cwe_evidence is None
        else build_scan_graph(
            ScanGraphServices(
                deterministic_scanner=_deterministic_scan,
                dependency_auditor=dependency_auditor,
                cwe_evidence=cwe_evidence,
            )
        )
    )
    report = _invoke_scan_graph(
        graph,
        target,
        limits,
        target_name=target_name,
        clock=clock,
    )
    if request_context_bound():
        log_scan_completed(
            scan_id=str(report.scan_id),
            counts={
                severity.value: count for severity, count in report.summary.by_severity.items()
            },
        )
    return report


class ScanService:
    """Stable application boundary shared by every delivery adapter."""

    def __init__(
        self,
        reports: ReportRepository,
        limits: ScanLimits | None = None,
        *,
        graph_services: ScanGraphServices | None = None,
    ) -> None:
        self._reports = reports
        self._limits = limits or ScanLimits()
        if graph_services is None:
            self._graph = _DEFAULT_SCAN_GRAPH
        else:
            services = graph_services
            if services.deterministic_scanner is None:
                services = replace(services, deterministic_scanner=_deterministic_scan)
            self._graph = build_scan_graph(services)

    def scan(
        self,
        target: Path,
        *,
        target_name: str | None = None,
        owner_member_id: UUID | None = None,
    ) -> ScanReport:
        """Scan a safe local target while preserving its public display name."""

        report = _invoke_scan_graph(
            self._graph,
            target,
            self._limits,
            target_name=target_name,
            clock=monotonic,
        )
        if owner_member_id is None:
            self._reports.save(report)
        else:
            self._reports.save(report, owner_member_id=owner_member_id)
        if request_context_bound():
            log_scan_completed(
                scan_id=str(report.scan_id),
                counts={
                    severity.value: count for severity, count in report.summary.by_severity.items()
                },
            )
        return report
