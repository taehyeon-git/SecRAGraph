"""Shared application service used by the API, CLI, and automation adapters."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from time import monotonic
from typing import cast

from security_review.domain.models import Finding, ScanReport
from security_review.observability import log_scan_completed, request_context_bound
from security_review.orchestrator.scan_graph import (
    DeterministicScanResult,
    ScanGraph,
    ScanGraphServices,
    ScanRequest,
    ScanState,
    ScanWorkflowError,
    build_scan_graph,
)
from security_review.ports import ReportRepository
from security_review.scanner.engine import scan_text_detailed
from security_review.scanner.files import ScanLimits, discover_files, read_scannable_text

PROCESSING_TIME_LIMIT_EXCEEDED = "processing_time_limit_exceeded"


class UnsupportedTargetError(ValueError):
    """Raised when an explicit single-file target has no supported source type."""


def _deterministic_scan(request: ScanRequest) -> DeterministicScanResult:
    """Run the bounded local scanner without any network or model dependency."""

    deadline = request.deadline
    if deadline is None:
        deadline = request.clock() + request.limits.max_processing_seconds
    discovery = discover_files(
        request.target,
        request.limits,
        deadline=deadline,
        clock=request.clock,
    )
    if (
        request.target.is_file()
        and not discovery.files
        and len(discovery.skipped) == 1
        and discovery.skipped[0].reason == "unsupported_extension"
    ):
        raise UnsupportedTargetError(f"unsupported_extension: {request.target.name}")

    warnings = list(discovery.warnings)
    warnings.extend(f"{item.path}:{item.reason}" for item in discovery.skipped)
    findings: list[Finding] = []
    if PROCESSING_TIME_LIMIT_EXCEEDED not in warnings:
        for file in discovery.files:
            if request.clock() >= deadline:
                warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
                break
            text = read_scannable_text(file, request.limits)
            if text is None:
                warnings.append(f"{file.relative_path}:file_changed_or_unreadable")
                continue
            if request.clock() >= deadline:
                warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
                break
            scan_result = scan_text_detailed(
                file.relative_path,
                text,
                should_stop=lambda: request.clock() >= deadline,
            )
            findings.extend(scan_result.findings)
            warnings.extend(
                warning
                if warning == PROCESSING_TIME_LIMIT_EXCEEDED
                else f"{file.relative_path}:{warning}"
                for warning in scan_result.warnings
            )
            if PROCESSING_TIME_LIMIT_EXCEEDED in scan_result.warnings:
                break
            if request.clock() >= deadline:
                warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
                break
    return DeterministicScanResult(
        target_name=request.target_name or request.target.name or "scan-target",
        findings=tuple(findings),
        warnings=tuple(warnings),
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
) -> ScanReport:
    """Scan one file or directory through the shared LangGraph engine."""

    report = _invoke_scan_graph(
        _DEFAULT_SCAN_GRAPH,
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

    def scan(self, target: Path, *, target_name: str | None = None) -> ScanReport:
        """Scan a safe local target while preserving its public display name."""

        report = _invoke_scan_graph(
            self._graph,
            target,
            self._limits,
            target_name=target_name,
            clock=monotonic,
        )
        self._reports.save(report)
        if request_context_bound():
            log_scan_completed(
                scan_id=str(report.scan_id),
                counts={
                    severity.value: count for severity, count in report.summary.by_severity.items()
                },
            )
        return report
