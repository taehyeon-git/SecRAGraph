"""HTTP contract for provider-backed security knowledge answers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.domain.models import SourceReference
from security_review.intelligence.fakes import (
    FakeChatModel,
    FakeDocumentRetriever,
    FakeKnowledgeRepository,
)
from security_review.intelligence.models import QueryResult
from security_review.intelligence.text2sql import Text2SqlService
from security_review.orchestrator.knowledge_graph import (
    KnowledgeService,
    KnowledgeServices,
    KnowledgeWorkflowError,
    build_knowledge_graph,
)
from security_review.orchestrator.state import KnowledgeAnswer
from security_review.ports import (
    IntelligenceConfigurationError,
    IntelligenceUnavailableError,
)


class FakeKnowledgeService:
    def __init__(self, responses: Sequence[object]) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def answer(self, question: str) -> KnowledgeAnswer:
        self.calls.append(question)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return cast(KnowledgeAnswer, response)


def _answer() -> KnowledgeAnswer:
    return KnowledgeAnswer(
        intent="rag",
        answer="Use an allowlisted parser.",
        attempts=1,
        sources=(
            SourceReference(
                id="guide:1",
                title="Secure parsing guide",
                source_url="https://example.com/guide",
                section="Expression handling",
                score=0.94,
            ),
        ),
        warnings=(),
    )


def _client(service: FakeKnowledgeService | None) -> TestClient:
    return TestClient(
        create_app(Settings(testing=True), knowledge_service=service),
        raise_server_exceptions=False,
    )


def test_knowledge_response_contains_route_attempts_and_sources() -> None:
    service = FakeKnowledgeService((_answer(),))

    response = _client(service).post(
        "/v1/knowledge/query",
        json={"question": "  CWE-95 완화 방법을 알려줘  "},
    )

    assert response.status_code == 200
    assert service.calls == ["CWE-95 완화 방법을 알려줘"]
    body = response.json()
    assert body == {
        "intent": "rag",
        "answer": "Use an allowlisted parser.",
        "attempts": 1,
        "sources": [
            {
                "id": "guide:1",
                "title": "Secure parsing guide",
                "source_url": "https://example.com/guide",
                "page": None,
                "section": "Expression handling",
                "score": 0.94,
            }
        ],
        "warnings": [],
    }


def test_text2sql_api_exposes_approved_query_provenance_without_rows() -> None:
    service = KnowledgeService(
        build_knowledge_graph(
            KnowledgeServices(
                chat_model=FakeChatModel(("text2sql",)),
                text2sql=Text2SqlService(
                    sql_model=FakeChatModel(("SELECT cwe_id FROM intel.cwe LIMIT 5",)),
                    answer_model=FakeChatModel(("One matching weakness.",)),
                    repository=FakeKnowledgeRepository(
                        QueryResult(columns=("cwe_id",), rows=(("PRIVATE-ROW",),))
                    ),
                    max_attempts=2,
                    row_limit=5,
                ),
                retriever=FakeDocumentRetriever(),
            )
        )
    )
    client = TestClient(
        create_app(Settings(testing=True), knowledge_service=service),
        raise_server_exceptions=False,
    )

    response = client.post("/v1/knowledge/query", json={"question": "Find a CWE"})

    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "text2sql"
    assert body["sources"] == [
        {
            "id": "sql:intel.cwe",
            "title": "Approved intelligence table: intel.cwe",
            "source_url": None,
            "page": None,
            "section": "SELECT cwe_id FROM intel.cwe LIMIT 5",
            "score": None,
        }
    ]
    assert "PRIVATE-ROW" not in response.text


def test_missing_provider_is_a_typed_503() -> None:
    response = _client(None).post(
        "/v1/knowledge/query",
        json={"question": "CVSS를 설명해줘"},
    )

    assert response.status_code == 503
    assert response.json()["code"] == "knowledge_provider_unavailable"


@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (
            IntelligenceConfigurationError(
                "private-api-key-must-not-leak",
                capability="chat",
            ),
            503,
            "knowledge_provider_unavailable",
        ),
        (
            IntelligenceUnavailableError("qdrant", "private-host-must-not-leak"),
            503,
            "knowledge_dependency_unavailable",
        ),
        (
            KnowledgeWorkflowError("private-model-output-must-not-leak"),
            502,
            "knowledge_response_invalid",
        ),
    ],
)
def test_expected_knowledge_failures_have_non_secret_error_codes(
    error: Exception,
    status_code: int,
    code: str,
) -> None:
    response = _client(FakeKnowledgeService((error,))).post(
        "/v1/knowledge/query",
        json={"question": "security question"},
    )

    assert response.status_code == status_code
    assert response.json()["code"] == code
    assert "private-" not in response.text


@pytest.mark.parametrize(
    "question",
    ["", "   ", "x" * 2_001, "contains\x00nul"],
)
def test_invalid_questions_stop_before_the_service(question: str) -> None:
    service = FakeKnowledgeService((_answer(),))

    response = _client(service).post(
        "/v1/knowledge/query",
        json={"question": question},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"
    assert service.calls == []


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"question": None},
        {"question": 42},
        {"question": True},
        {"question": ["security"]},
    ],
)
def test_non_text_questions_stop_before_the_service(payload: object) -> None:
    service = FakeKnowledgeService((_answer(),))

    response = _client(service).post("/v1/knowledge/query", json=payload)

    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"
    assert service.calls == []


def test_question_at_the_exact_limit_is_accepted_after_trimming() -> None:
    service = FakeKnowledgeService((_answer(),))
    question = "x" * 2_000

    response = _client(service).post(
        "/v1/knowledge/query",
        json={"question": f"  {question}  "},
    )

    assert response.status_code == 200
    assert service.calls == [question]


def test_extra_request_fields_are_rejected() -> None:
    response = _client(FakeKnowledgeService((_answer(),))).post(
        "/v1/knowledge/query",
        json={"question": "What is a CVE?", "route": "text2sql"},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_unexpected_service_errors_use_the_existing_internal_error_envelope() -> None:
    response = _client(
        FakeKnowledgeService((RuntimeError("private-stack-detail-must-not-leak"),))
    ).post(
        "/v1/knowledge/query",
        json={"question": "What is a CVE?"},
    )

    assert response.status_code == 500
    assert response.json()["code"] == "internal_error"
    assert "private-stack-detail" not in response.text


@pytest.mark.parametrize(
    ("error", "expected_message"),
    [
        (
            IntelligenceConfigurationError("secret", capability="chat"),
            "The security knowledge provider is not configured.",
        ),
        (
            IntelligenceUnavailableError("qdrant", "secret"),
            "A security knowledge dependency is unavailable.",
        ),
        (
            KnowledgeWorkflowError("secret"),
            "The security knowledge response was invalid.",
        ),
    ],
)
def test_expected_failures_have_fixed_messages_and_correlation_ids(
    error: Exception,
    expected_message: str,
) -> None:
    response = _client(FakeKnowledgeService((error,))).post(
        "/v1/knowledge/query",
        json={"question": "security question"},
    )

    body = response.json()
    assert body["message"] == expected_message
    assert response.headers["X-Correlation-ID"] == body["correlation_id"]
    UUID(body["correlation_id"])


def test_invalid_service_output_is_a_sanitized_internal_error() -> None:
    response = _client(FakeKnowledgeService(({"answer": "missing contract"},))).post(
        "/v1/knowledge/query",
        json={"question": "security question"},
    )

    assert response.status_code == 500
    assert response.json()["code"] == "internal_error"
    assert "missing contract" not in response.text
