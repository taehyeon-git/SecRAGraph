"""Privacy and correlation contracts at the logging boundary."""

from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from security_review.api.app import create_app
from security_review.application import ScanService
from security_review.audit import AuditEvent
from security_review.config import Settings
from security_review.intelligence.fakes import (
    FakeChatModel,
    FakeDocumentRetriever,
    FakeKnowledgeRepository,
)
from security_review.intelligence.text2sql import Text2SqlService
from security_review.observability import (
    bind_audit_sink,
    bind_context,
    configure_logging,
    log_route_selected,
    log_scan_completed,
)
from security_review.orchestrator.knowledge_graph import KnowledgeServices, build_knowledge_graph
from security_review.ports import IntelligenceUnavailableError
from security_review.storage.memory import InMemoryReportRepository


class _RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


def _knowledge_services(
    model_responses: tuple[str, ...], retriever: FakeDocumentRetriever
) -> KnowledgeServices:
    model = FakeChatModel(model_responses)
    return KnowledgeServices(
        chat_model=model,
        text2sql=Text2SqlService(
            sql_model=model,
            answer_model=model,
            repository=FakeKnowledgeRepository.empty(),
            max_attempts=2,
            row_limit=5,
        ),
        retriever=retriever,
        max_rag_attempts=2,
    )


def test_logs_exclude_scanned_secret(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("production")
    secret = "sk-live-value-that-must-not-appear"

    log_scan_completed(scan_id=str(uuid4()), counts={"high": 1}, raw_match=secret)

    event = json.loads(capsys.readouterr().out)
    assert event["event"] == "scan_completed"
    assert event["high_count"] == 1
    assert secret not in json.dumps(event)


def test_logging_configuration_does_not_retain_a_closed_output_stream(
    capsys: pytest.CaptureFixture[str],
) -> None:
    temporary_stream = StringIO()
    with redirect_stdout(temporary_stream):
        configure_logging("production")
    temporary_stream.close()

    log_route_selected("text2sql")

    assert json.loads(capsys.readouterr().out)["route"] == "text2sql"


def test_bound_correlation_is_emitted_only_for_its_request(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("production")
    correlation = str(uuid4())

    with bind_context(correlation, None):
        log_route_selected("rag")
    log_route_selected("general")

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0]["correlation_id"] == correlation
    assert "correlation_id" not in events[1]
    assert events[0]["route"] == "rag"


def test_request_reuses_valid_correlation_id() -> None:
    caller_id = str(uuid4())
    response = TestClient(create_app(Settings(testing=True))).get(
        "/health/live", headers={"X-Correlation-ID": caller_id}
    )

    assert response.headers["X-Correlation-ID"] == caller_id


def test_invalid_correlation_is_replaced_and_exception_response_has_it() -> None:
    app = create_app(Settings(testing=True))

    @app.get("/failure")
    def failure() -> None:
        raise RuntimeError("password-in-internal-error")

    response = TestClient(app, raise_server_exceptions=False).get(
        "/failure", headers={"X-Correlation-ID": "test-correlation"}
    )

    replacement = response.headers["X-Correlation-ID"]
    UUID(replacement)
    assert replacement != "test-correlation"
    assert response.json()["correlation_id"] == replacement
    assert "password-in-internal-error" not in response.text


def test_graph_route_and_retry_audit_omit_question_and_retrieved_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("production")
    question = "secret-user-question"
    sink = _RecordingAuditSink()
    services = _knowledge_services(
        ("rag", "rewritten query"),
        FakeDocumentRetriever(responses={question: (), "rewritten query": ()}),
    )

    with bind_context(str(uuid4()), None), bind_audit_sink(sink):
        build_knowledge_graph(services).invoke({"question": question})

    assert [event.event_type for event in sink.events] == [
        "route_selected",
        "retry_performed",
    ]
    assert sink.events[0].attributes == {"route": "rag", "defaulted": False}
    assert sink.events[1].attributes == {"route": "rag", "attempt": 2}
    assert question not in capsys.readouterr().out
    assert question not in repr(sink.events)


def test_dependency_failure_audit_omits_provider_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("production")
    sink = _RecordingAuditSink()
    services = _knowledge_services(
        ("rag",),
        FakeDocumentRetriever(
            failure=IntelligenceUnavailableError("qdrant", "secret-provider-message")
        ),
    )

    with bind_context(str(uuid4()), None), bind_audit_sink(sink):
        with pytest.raises(IntelligenceUnavailableError):
            build_knowledge_graph(services).invoke({"question": "secret-user-question"})

    assert [event.event_type for event in sink.events] == [
        "route_selected",
        "dependency_failed",
    ]
    assert sink.events[-1].attributes == {"dependency": "qdrant", "reason": "unavailable"}
    output = capsys.readouterr().out
    assert "secret-provider-message" not in output
    assert "secret-user-question" not in output


def test_scan_lifecycle_audit_contains_only_generated_id_and_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging("production")
    target = tmp_path / "app.py"
    target.write_text("password = 'sk-live-private-value'\n", encoding="utf-8")
    sink = _RecordingAuditSink()

    with bind_context(str(uuid4()), None), bind_audit_sink(sink):
        report = ScanService(InMemoryReportRepository()).scan(target)

    assert [event.event_type for event in sink.events] == ["scan_started", "scan_completed"]
    assert sink.events[0].scan_id is None
    assert sink.events[1].scan_id == str(report.scan_id)
    assert "sk-live-private-value" not in capsys.readouterr().out
    assert "sk-live-private-value" not in repr(sink.events)
