"""Allowlisted structured logs and request-scoped audit emission."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Literal
from uuid import UUID

import structlog
from structlog.contextvars import bind_contextvars, get_contextvars, reset_contextvars

from security_review.audit import AuditEvent, AuditEventType, AuditSink, AuditValue

_audit_sink: ContextVar[AuditSink | None] = ContextVar("audit_sink", default=None)
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_ROUTES = {"general", "text2sql", "rag", "answer", "rewrite", "stop"}
_DEPENDENCIES = {"embedding", "qdrant", "rag", "chat", "llm", "sql"}


def configure_logging(environment: str) -> None:
    """Use JSON on deployed hosts and readable structured output locally."""

    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if environment in {"production", "container", "test"}
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            renderer,
        ],
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


@contextmanager
def bind_context(correlation_id: str, scan_id: str | None) -> Iterator[None]:
    """Bind canonical identifiers only for the active operation."""

    canonical_correlation = str(UUID(correlation_id))
    canonical_scan = str(UUID(scan_id)) if scan_id is not None else None
    tokens = dict(bind_contextvars(correlation_id=canonical_correlation))
    if canonical_scan is not None:
        tokens.update(bind_contextvars(scan_id=canonical_scan))
    try:
        yield
    finally:
        reset_contextvars(**tokens)


@contextmanager
def bind_audit_sink(sink: AuditSink | None) -> Iterator[None]:
    """Attach a sink to one request without leaking it to another."""

    token = _audit_sink.set(sink)
    try:
        yield
    finally:
        _audit_sink.reset(token)


def request_context_bound() -> bool:
    """Whether this operation has a request correlation ID for audit emission."""

    return isinstance(get_contextvars().get("correlation_id"), str)


def _emit(
    event_type: AuditEventType,
    attributes: dict[str, AuditValue],
    *,
    scan_id: str | None = None,
) -> None:
    context = get_contextvars()
    effective_scan_id = scan_id or context.get("scan_id")
    logger = structlog.get_logger()
    log_fields = {**attributes, **({"scan_id": effective_scan_id} if effective_scan_id else {})}
    logger.info(event_type, **log_fields)
    correlation_id = context.get("correlation_id")
    sink = _audit_sink.get()
    if sink is None or not isinstance(correlation_id, str):
        return
    event = AuditEvent(
        event_type=event_type,
        correlation_id=correlation_id,
        scan_id=effective_scan_id if isinstance(effective_scan_id, str) else None,
        attributes=attributes,
    )
    try:
        sink.record(event)
    except Exception:
        logger.warning("audit_write_failed")


def log_scan_started() -> None:
    _emit("scan_started", {})


def log_scan_completed(
    *,
    scan_id: str,
    counts: Mapping[str, int],
    raw_match: str | None = None,
) -> None:
    """Emit generated scan ID and severity totals; discard raw scanner text."""

    del raw_match
    attributes: dict[str, AuditValue] = {}
    for key, value in counts.items():
        if key in _SEVERITIES and type(value) is int and 0 <= value <= 1_000_000_000:
            attributes[f"{key}_count"] = value
    _emit("scan_completed", attributes, scan_id=scan_id)


def log_route_selected(route: str, *, defaulted: bool = False) -> None:
    if route not in _ROUTES:
        return
    _emit("route_selected", {"route": route, "defaulted": defaulted})


def log_retry_performed(route: str, attempt: int) -> None:
    if route not in _ROUTES or type(attempt) is not int or not 1 <= attempt <= 1_000_000_000:
        return
    _emit("retry_performed", {"route": route, "attempt": attempt})


def log_dependency_failed(
    dependency: str,
    reason: Literal["unavailable", "configuration", "invalid_response", "timeout"],
) -> None:
    if dependency not in _DEPENDENCIES:
        dependency = "rag"
    _emit("dependency_failed", {"dependency": dependency, "reason": reason})
