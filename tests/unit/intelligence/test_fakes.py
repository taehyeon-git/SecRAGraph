"""Contract tests for deterministic security-intelligence test doubles."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_review.config import Settings
from security_review.intelligence.fakes import (
    FakeChatModel,
    FakeDocumentRetriever,
    FakeEmbeddingModel,
    FakeKnowledgeRepository,
    FakeResponseExhaustedError,
)
from security_review.intelligence.models import DocumentChunk, QueryResult
from security_review.ports import IntelligenceUnavailableError


def _chunk(identifier: str = "doc:1") -> DocumentChunk:
    return DocumentChunk(
        id=identifier,
        text="Use parameterized queries.",
        title="Secure SQL",
        source_url="https://example.invalid/secure-sql",
        page=None,
        section="Injection prevention",
        score=0.91,
    )


def test_fake_chat_model_records_calls_and_returns_fifo_responses() -> None:
    model = FakeChatModel(["first", "second"])

    assert model.complete("system", "question") == "first"
    assert model.complete("system-2", "question-2") == "second"
    assert model.calls == [
        ("system", "question"),
        ("system-2", "question-2"),
    ]


def test_fake_chat_model_fails_predictably_when_responses_are_exhausted() -> None:
    model = FakeChatModel([])

    with pytest.raises(FakeResponseExhaustedError, match="no configured response"):
        model.complete("system", "question")

    assert model.calls == [("system", "question")]


def test_fake_chat_model_can_raise_a_configured_provider_failure() -> None:
    failure = IntelligenceUnavailableError("chat", "provider_unavailable")
    model = FakeChatModel([failure])

    with pytest.raises(IntelligenceUnavailableError, match="chat: provider_unavailable"):
        model.complete("system", "question")


def test_fake_retriever_returns_configured_chunks_with_a_limit() -> None:
    first = _chunk("doc:1")
    second = _chunk("doc:2")
    retriever = FakeDocumentRetriever({"sql injection": (first, second)})

    assert retriever.search("sql injection", 1) == (first,)
    assert retriever.calls == [("sql injection", 1)]


def test_fake_retriever_uses_mutable_default_results_for_graph_scenarios() -> None:
    retriever = FakeDocumentRetriever()
    retriever.results = (_chunk(),)

    assert retriever.search("unmapped question") == retriever.results


def test_fake_embedding_model_records_batches_and_is_deterministic() -> None:
    embeddings = FakeEmbeddingModel(dimension=4)

    first = embeddings.embed(["same text", "different text"])
    second = embeddings.embed(["same text"])

    assert embeddings.dimension == 4
    assert first[0] == second[0]
    assert len(first) == 2
    assert all(len(vector) == 4 for vector in first)
    assert embeddings.calls == [
        ("same text", "different text"),
        ("same text",),
    ]


def test_fake_embedding_model_rejects_a_configured_vector_dimension_mismatch() -> None:
    with pytest.raises(ValueError, match="configured vector.*dimension 3"):
        FakeEmbeddingModel(dimension=3, vectors={"query": [0.1, 0.2]})


def test_fake_knowledge_repository_returns_immutable_result_and_records_sql() -> None:
    result = QueryResult(columns=("cwe_id",), rows=(("CWE-95",),))
    repository = FakeKnowledgeRepository(result)

    assert repository.execute_readonly("SELECT cwe_id FROM intel.cwe") == result
    assert repository.queries == ["SELECT cwe_id FROM intel.cwe"]
    assert repository.mutations == []

    with pytest.raises(ValidationError):
        result.rows = ()  # type: ignore[misc]


def test_fake_knowledge_repository_records_and_rejects_mutation_attempts() -> None:
    repository = FakeKnowledgeRepository.empty()

    with pytest.raises(AssertionError, match="read-only fake received mutation"):
        repository.execute_readonly("DELETE FROM intel.cwe")

    assert repository.mutations == ["DELETE FROM intel.cwe"]
    assert repository.queries == ["DELETE FROM intel.cwe"]


def test_query_result_rejects_rows_that_do_not_match_column_count() -> None:
    with pytest.raises(ValidationError, match="same number of values"):
        QueryResult(columns=("cwe_id", "name"), rows=(("CWE-95",),))


def test_document_chunk_converts_to_a_domain_source_reference() -> None:
    chunk = _chunk()

    reference = chunk.to_source_reference()

    assert reference.model_dump() == {
        "id": "doc:1",
        "title": "Secure SQL",
        "source_url": "https://example.invalid/secure-sql",
        "page": None,
        "section": "Injection prevention",
        "score": 0.91,
    }


def test_intelligence_settings_are_bounded_and_provider_key_is_optional() -> None:
    settings = Settings(_env_file=None)

    assert settings.openai_api_key is None
    assert settings.qdrant_api_key is None
    assert settings.intelligence_database_url is None
    assert settings.openai_embedding_model == "text-embedding-3-small"
    assert settings.qdrant_min_score == 0.25
    assert settings.qdrant_search_limit == 20
    assert settings.max_rag_attempts == 2
    assert settings.max_sql_attempts == 2
    assert settings.sql_statement_timeout_ms == 2_000
    assert settings.sql_row_limit == 100

    with pytest.raises(ValidationError):
        Settings(_env_file=None, qdrant_vector_dimension=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, qdrant_min_score=1.1)
    assert Settings(_env_file=None, max_rag_attempts=5).max_rag_attempts == 5
    with pytest.raises(ValidationError):
        Settings(_env_file=None, max_rag_attempts=6)
