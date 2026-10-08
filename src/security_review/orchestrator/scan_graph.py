"""Deterministic-first LangGraph workflow for scan enrichment and reporting."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Protocol, TypeAlias, TypedDict, cast
from urllib.parse import urlsplit

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from security_review.domain.models import (
    Finding,
    ReportSummary,
    RiskSummary,
    ScanReport,
    ScanStatus,
    SourceReference,
)
from security_review.domain.risk import calculate_risk as calculate_risk_summary
from security_review.intelligence.models import DocumentChunk
from security_review.observability import (
    log_dependency_failed,
    log_scan_started,
    request_context_bound,
)
from security_review.ports import (
    ChatModel,
    IntelligenceConfigurationError,
    IntelligenceUnavailableError,
    SecurityDocumentRetriever,
)
from security_review.reporting.builder import build_report as assemble_report
from security_review.reporting.builder import normalize_findings as normalize_report_findings
from security_review.reporting.builder import normalize_target_name, normalize_warnings
from security_review.scanner.files import ScanLimits

MAX_QUERY_CHARACTERS = 2_000
MAX_CHUNK_BYTES = 32_000
MAX_EVIDENCE_BYTES = 128_000
PROCESSING_TIME_LIMIT_EXCEEDED = "processing_time_limit_exceeded"


class ScanWorkflowError(RuntimeError):
    """Raised when the scan graph reaches an invalid internal state."""


class _EnrichmentDeadlineReached(RuntimeError):
    """Internal control signal used to preserve deterministic partial results."""


@dataclass(frozen=True, slots=True)
class ScanRequest:
    """Validated deterministic scan input passed through a narrow callable port."""

    target: Path
    limits: ScanLimits
    target_name: str | None = None
    clock: Callable[[], float] = field(default=monotonic, repr=False, compare=False)
    deadline: float | None = None


@dataclass(frozen=True, slots=True)
class DeterministicScanResult:
    """Provider-free scan output used as the immutable enrichment baseline."""

    target_name: str
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()


class DeterministicScanner(Protocol):
    """Execute the local scanner without running target code."""

    def __call__(self, request: ScanRequest) -> DeterministicScanResult: ...


class ReportBuilder(Protocol):
    """Build the canonical report shared by every delivery adapter."""

    def __call__(
        self,
        target_name: str,
        findings: Sequence[Finding],
        warnings: Sequence[str] = (),
    ) -> ScanReport: ...


class ScanState(TypedDict, total=False):
    """State carried by the explicit scan-enrichment graph."""

    target: Path
    limits: ScanLimits
    target_name: str | None
    clock: Callable[[], float]
    deadline: float | None
    request: ScanRequest | None
    input_findings: tuple[Finding, ...]
    deterministic_findings: tuple[Finding, ...]
    findings: tuple[Finding, ...]
    deterministic_warnings: tuple[str, ...]
    warnings: tuple[str, ...]
    risk: RiskSummary | None
    report: ScanReport | None


ScanGraph: TypeAlias = CompiledStateGraph[
    ScanState,
    None,
    ScanState,
    ScanState,
]


@dataclass(frozen=True, slots=True)
class ScanGraphServices:
    """Dependencies and hard cost bounds captured by a compiled scan graph."""

    deterministic_scanner: DeterministicScanner | None = None
    retriever: SecurityDocumentRetriever | None = None
    chat_model: ChatModel | None = None
    report_builder: ReportBuilder = assemble_report
    retrieval_limit: int = 5
    max_enriched_findings: int = 20

    def __post_init__(self) -> None:
        if type(self.retrieval_limit) is not int or not 1 <= self.retrieval_limit <= 20:
            raise ValueError("retrieval_limit must be between 1 and 20")
        if (
            type(self.max_enriched_findings) is not int
            or not 1 <= self.max_enriched_findings <= 100
        ):
            raise ValueError("max_enriched_findings must be between 1 and 100")


def build_scan_graph(services: ScanGraphServices) -> ScanGraph:
    """Compile the linear deterministic-scan, enrichment, and reporting workflow."""

    def validate_input(state: ScanState) -> ScanState:
        target = state.get("target")
        if target is not None:
            if not isinstance(target, Path):
                raise ValueError("target must be a pathlib.Path")
            limits = state.get("limits")
            if not isinstance(limits, ScanLimits):
                raise ValueError("limits must be ScanLimits")
            target_name = _validated_target_name(state.get("target_name"))
            clock = state.get("clock", monotonic)
            if not callable(clock):
                raise ValueError("clock must be callable")
            started_at = clock()
            if (
                isinstance(started_at, bool)
                or not isinstance(started_at, (int, float))
                or not math.isfinite(float(started_at))
            ):
                raise ValueError("clock must return a finite number")
            deadline = float(started_at) + limits.max_processing_seconds
            request: ScanRequest | None = ScanRequest(
                target=target,
                limits=limits,
                target_name=target_name,
                clock=clock,
                deadline=deadline,
            )
            input_findings: tuple[Finding, ...] = ()
            resolved_name = target_name
        else:
            request = None
            deadline = None
            input_findings = _validated_finding_tuple(state.get("findings"))
            resolved_name = _validated_target_name(state.get("target_name")) or "scan-target"
        if request_context_bound():
            log_scan_started()
        return {
            "request": request,
            "target_name": resolved_name,
            "deadline": deadline,
            "input_findings": input_findings,
            "deterministic_findings": (),
            "findings": (),
            "deterministic_warnings": (),
            "warnings": (),
            "risk": None,
            "report": None,
        }

    def deterministic_scan(state: ScanState) -> ScanState:
        request = state.get("request")
        if request is None:
            findings = _required_findings(state, "input_findings")
            return {
                "deterministic_findings": findings,
                "findings": findings,
                "deterministic_warnings": (),
                "warnings": (),
            }
        if services.deterministic_scanner is None:
            raise ScanWorkflowError("missing_deterministic_scanner")
        result = services.deterministic_scanner(request)
        if not isinstance(result, DeterministicScanResult):
            raise ScanWorkflowError("invalid_deterministic_scan_result")
        target_name = _validated_target_name(result.target_name)
        if target_name is None:
            raise ScanWorkflowError("invalid_deterministic_target_name")
        findings = _validated_finding_tuple(result.findings)
        warnings = _validated_warning_tuple(result.warnings)
        return {
            "target_name": target_name,
            "deterministic_findings": findings,
            "findings": findings,
            "deterministic_warnings": warnings,
            "warnings": warnings,
        }

    def normalize_findings(state: ScanState) -> ScanState:
        findings = normalize_report_findings(_required_findings(state, "deterministic_findings"))
        return {
            "deterministic_findings": findings,
            "findings": findings,
        }

    def retrieve_finding_evidence(state: ScanState) -> ScanState:
        baseline = _required_findings(state, "deterministic_findings")
        warnings = _required_warnings(state)
        if services.retriever is None or not baseline:
            return {"findings": baseline}
        if PROCESSING_TIME_LIMIT_EXCEEDED in warnings:
            return {"findings": baseline}

        limited = baseline[: services.max_enriched_findings]
        if len(baseline) > len(limited):
            warnings = _append_warning(warnings, "enrichment_finding_limit_reached")
        enriched = list(baseline)
        active_phase = "rag"
        try:
            for index, finding in enumerate(limited):
                _require_enrichment_time(state)
                active_phase = "rag"
                chunks = _validated_chunks(
                    services.retriever.search(
                        _finding_query(finding),
                        limit=services.retrieval_limit,
                    ),
                    services.retrieval_limit,
                )
                _require_enrichment_time(state)
                if not chunks:
                    continue
                references = _merge_references(
                    finding.references,
                    tuple(chunk.to_source_reference() for chunk in chunks),
                )
                enriched[index] = _rebuild_enriched_finding(
                    finding,
                    references=references,
                    remediation=finding.remediation,
                )
        except IntelligenceConfigurationError as error:
            warning = _configuration_warning(error, active_phase)
            log_dependency_failed(error.capability or active_phase, "configuration")
            return {
                "findings": baseline,
                "warnings": _append_warning(warnings, warning),
            }
        except IntelligenceUnavailableError as error:
            warning = _provider_warning(error, active_phase)
            log_dependency_failed(error.capability, "unavailable")
            return {
                "findings": baseline,
                "warnings": _append_warning(warnings, warning),
            }
        except _EnrichmentDeadlineReached:
            return {
                "findings": baseline,
                "warnings": _append_warning(warnings, PROCESSING_TIME_LIMIT_EXCEEDED),
            }
        return {"findings": tuple(enriched), "warnings": warnings}

    def calculate_risk(state: ScanState) -> ScanState:
        findings = _required_findings(state, "findings")
        return {"risk": calculate_risk_summary(findings)}

    def build_report(state: ScanState) -> ScanState:
        target_name = _validated_target_name(state.get("target_name"))
        if target_name is None:
            raise ScanWorkflowError("missing_target_name")
        findings = _required_findings(state, "findings")
        warnings = _required_warnings(state)
        risk = state.get("risk")
        if not isinstance(risk, RiskSummary):
            raise ScanWorkflowError("missing_risk")
        report = services.report_builder(target_name, findings, warnings)
        expected_warnings = normalize_warnings(warnings)
        expected_status = (
            ScanStatus.COMPLETED_WITH_WARNINGS if expected_warnings else ScanStatus.COMPLETED
        )
        if (
            not isinstance(report, ScanReport)
            or report.target_name != normalize_target_name(target_name)
            or report.findings != findings
            or report.warnings != expected_warnings
            or report.status is not expected_status
            or report.summary != ReportSummary.from_findings(findings)
            or report.risk != risk
        ):
            raise ScanWorkflowError("invalid_report")
        return {"report": report}

    builder: StateGraph[ScanState, None, ScanState, ScanState] = StateGraph(ScanState)
    builder.add_node("validate_input", validate_input)
    builder.add_node("deterministic_scan", deterministic_scan)
    builder.add_node("normalize_findings", normalize_findings)
    builder.add_node("retrieve_finding_evidence", retrieve_finding_evidence)
    builder.add_node("calculate_risk", calculate_risk)
    builder.add_node("build_report", build_report)
    builder.add_edge(START, "validate_input")
    builder.add_edge("validate_input", "deterministic_scan")
    builder.add_edge("deterministic_scan", "normalize_findings")
    builder.add_edge("normalize_findings", "retrieve_finding_evidence")
    builder.add_edge("retrieve_finding_evidence", "calculate_risk")
    builder.add_edge("calculate_risk", "build_report")
    builder.add_edge("build_report", END)
    return builder.compile()


def _validated_target_name(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("target_name must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > 1_024 or _contains_control(normalized):
        raise ValueError("target_name is invalid")
    return normalized


def _validated_finding_tuple(value: object) -> tuple[Finding, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, Finding) for item in value):
        raise ValueError("findings must be a tuple of Finding values")
    return cast(tuple[Finding, ...], value)


def _validated_warning_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) and item for item in value):
        raise ScanWorkflowError("invalid_deterministic_warnings")
    return cast(tuple[str, ...], value)


def _required_findings(state: ScanState, key: str) -> tuple[Finding, ...]:
    return _validated_finding_tuple(state.get(key))


def _required_warnings(state: ScanState) -> tuple[str, ...]:
    warnings = state.get("warnings")
    if not isinstance(warnings, tuple) or not all(
        isinstance(item, str) and item for item in warnings
    ):
        raise ScanWorkflowError("invalid_warnings")
    return warnings


def _finding_query(finding: Finding) -> str:
    components = [
        "security remediation",
        finding.rule_id,
        finding.category,
        *finding.cwe_ids,
        finding.message,
    ]
    normalized = " ".join(" ".join(components).split())
    return normalized[:MAX_QUERY_CHARACTERS]


def _validated_chunks(value: object, limit: int) -> tuple[DocumentChunk, ...]:
    if not isinstance(value, tuple) or len(value) > limit:
        raise IntelligenceUnavailableError("rag", "invalid_retrieval_response")
    validated: list[DocumentChunk] = []
    seen: dict[str, DocumentChunk] = {}
    total_bytes = 0
    for chunk in value:
        if not isinstance(chunk, DocumentChunk) or not _safe_chunk_metadata(chunk):
            raise IntelligenceUnavailableError("rag", "invalid_retrieval_response")
        if not _is_strict_utf8(chunk.text):
            raise IntelligenceUnavailableError("rag", "invalid_retrieval_response")
        chunk_bytes = len(chunk.text.encode("utf-8"))
        total_bytes += chunk_bytes
        if (
            chunk_bytes > MAX_CHUNK_BYTES
            or total_bytes > MAX_EVIDENCE_BYTES
            or not chunk.text.strip()
            or "\x00" in chunk.text
        ):
            raise IntelligenceUnavailableError("rag", "invalid_retrieval_response")
        previous = seen.get(chunk.id)
        if previous is not None:
            if previous != chunk:
                raise IntelligenceUnavailableError("rag", "invalid_retrieval_response")
            continue
        seen[chunk.id] = chunk
        validated.append(chunk)
    return tuple(validated)


def _safe_chunk_metadata(chunk: DocumentChunk) -> bool:
    if (
        not isinstance(chunk.id, str)
        or not isinstance(chunk.text, str)
        or not isinstance(chunk.title, str)
        or (chunk.source_url is not None and not isinstance(chunk.source_url, str))
        or (chunk.section is not None and not isinstance(chunk.section, str))
        or (chunk.page is not None and (type(chunk.page) is not int or chunk.page < 1))
        or isinstance(chunk.score, bool)
        or not isinstance(chunk.score, (int, float))
        or not chunk.id.strip()
        or not chunk.title.strip()
        or len(chunk.id) > 1_024
        or len(chunk.title) > 300
        or (chunk.section is not None and not chunk.section.strip())
        or (chunk.section is not None and len(chunk.section) > 500)
        or (chunk.page is not None and chunk.page > 1_000_000)
        or _contains_control(chunk.id)
        or _contains_control(chunk.title)
        or (chunk.section is not None and _contains_control(chunk.section))
        or not _is_strict_utf8(chunk.id)
        or not _is_strict_utf8(chunk.title)
        or (chunk.section is not None and not _is_strict_utf8(chunk.section))
        or not math.isfinite(float(chunk.score))
    ):
        return False
    if chunk.source_url is None:
        return True
    if (
        len(chunk.source_url) > 2_048
        or _contains_control(chunk.source_url)
        or not _is_strict_utf8(chunk.source_url)
    ):
        return False
    try:
        parsed = urlsplit(chunk.source_url)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _merge_references(
    existing: tuple[SourceReference, ...],
    retrieved: tuple[SourceReference, ...],
) -> tuple[SourceReference, ...]:
    merged: list[SourceReference] = []
    by_id: dict[str, SourceReference] = {}
    for reference in (*existing, *retrieved):
        previous = by_id.get(reference.id)
        if previous is not None:
            if previous != reference:
                raise IntelligenceUnavailableError("rag", "conflicting_reference_id")
            continue
        by_id[reference.id] = reference
        merged.append(reference)
    return tuple(merged)


def _rebuild_enriched_finding(
    finding: Finding,
    *,
    references: tuple[SourceReference, ...],
    remediation: str,
) -> Finding:
    enriched = Finding(
        id=finding.id,
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        message=finding.message,
        redacted_evidence=finding.redacted_evidence,
        confidence=finding.confidence,
        cwe_ids=finding.cwe_ids,
        remediation=remediation,
        references=references,
    )
    if _protected_fields(enriched) != _protected_fields(finding):
        raise ScanWorkflowError("protected_finding_fields_changed")
    return enriched


def _protected_fields(finding: Finding) -> tuple[object, ...]:
    return (
        finding.id,
        finding.rule_id,
        finding.category,
        finding.severity,
        finding.file_path,
        finding.line_start,
        finding.line_end,
        finding.message,
        finding.redacted_evidence,
        finding.confidence,
        finding.cwe_ids,
    )


def _provider_warning(error: IntelligenceUnavailableError, active_phase: str) -> str:
    return _capability_warning(error.capability, active_phase, error)


def _configuration_warning(
    error: IntelligenceConfigurationError,
    active_phase: str,
) -> str:
    if error.capability is None:
        return f"enrichment_{active_phase}_unavailable"
    return _capability_warning(error.capability, active_phase, error)


def _capability_warning(
    capability: str,
    active_phase: str,
    error: IntelligenceConfigurationError | IntelligenceUnavailableError,
) -> str:
    warnings = {
        "embedding": "enrichment_embedding_unavailable",
        "qdrant": "enrichment_qdrant_unavailable",
        "rag": "enrichment_rag_unavailable",
        "chat": "enrichment_chat_unavailable",
        "llm": "enrichment_llm_unavailable",
    }
    warning = warnings.get(capability)
    allowed = {
        "rag": {"embedding", "qdrant", "rag"},
        "llm": {"chat", "llm"},
    }
    if warning is None or capability not in allowed.get(active_phase, set()):
        raise error
    return warning


def _require_enrichment_time(state: ScanState) -> None:
    request = state.get("request")
    deadline = state.get("deadline")
    if request is None or deadline is None:
        return
    if request.clock() >= deadline:
        raise _EnrichmentDeadlineReached


def _is_strict_utf8(value: str) -> bool:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return True


def _append_warning(warnings: tuple[str, ...], warning: str) -> tuple[str, ...]:
    if warning in warnings:
        return warnings
    return (*warnings, warning)


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
