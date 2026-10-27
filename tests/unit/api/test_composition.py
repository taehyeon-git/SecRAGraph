"""Production composition must respect missing credentials and owned lifecycles."""

from __future__ import annotations

from fastapi.testclient import TestClient
from pydantic import SecretStr
from qdrant_client import QdrantClient

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.domain.models import SourceReference
from security_review.intelligence.dynamic_cwe import CweEvidenceResult
from security_review.intelligence.fakes import FakeChatModel, FakeEmbeddingModel
from security_review.intelligence.ingestion import KnowledgeDocument, chunk_documents
from security_review.intelligence.qdrant_retriever import QdrantDocumentRetriever


def test_missing_openai_key_keeps_knowledge_unavailable_and_liveness_healthy() -> None:
    app = create_app(Settings(testing=True, openai_api_key=None))

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200
        response = client.post("/v1/knowledge/query", json={"question": "What is CWE-89?"})

    assert response.status_code == 503
    assert response.json()["code"] == "knowledge_provider_unavailable"


def test_injected_local_adapters_enable_knowledge_without_cloud_key() -> None:
    app = create_app(
        Settings(testing=True, intelligence_database_url="sqlite://", openai_api_key=None),
        chat_model=FakeChatModel(("general", "Parameterized queries prevent SQL injection.")),
        embeddings=FakeEmbeddingModel(dimension=3),
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/knowledge/query",
            json={"question": "Explain parameterized queries"},
        )

    assert response.status_code == 200
    assert response.json()["intent"] == "general"


def test_new_api_rag_question_indexes_its_cwe_before_search() -> None:
    question = "How should CWE-918 be mitigated?"
    source_url = "https://cwe-api.mitre.org/api/v1/cwe/weakness/918"
    document = KnowledgeDocument(
        source_path="cwe-918.md",
        title="CWE-918: Server-Side Request Forgery",
        text="Restrict outbound destinations and validate request URLs.",
        source_url=source_url,
        corpus_id="secragraph-runtime-cwe-v1",
    )
    chunks = chunk_documents((document,), 350, 50)
    embeddings = FakeEmbeddingModel(
        dimension=3,
        vectors={question: [1.0, 0.0, 0.0], chunks[0].text: [1.0, 0.0, 0.0]},
    )
    qdrant = QdrantClient(location=":memory:")
    indexer = QdrantDocumentRetriever(qdrant, embeddings, "dynamic-cwe-test", min_score=0.0)
    indexer.ensure_collection()
    requested: list[tuple[str, ...]] = []

    class Provider:
        def ensure(
            self, ids: tuple[str, ...], *, deadline: float | None = None
        ) -> CweEvidenceResult:
            del deadline
            requested.append(tuple(ids))
            indexer.replace_documents(chunks)
            return CweEvidenceResult(
                {
                    "CWE-918": SourceReference(
                        id="mitre:CWE-918", title=document.title, source_url=source_url
                    )
                }
            )

    model = FakeChatModel(
        (
            '{"route":"rag","cwe_ids":["CWE-918"]}',
            f"Restrict outbound destinations [source:{chunks[0].id}].",
        )
    )
    app = create_app(
        Settings(
            testing=True,
            intelligence_database_url="sqlite://",
            qdrant_collection="dynamic-cwe-test",
            qdrant_vector_dimension=3,
            qdrant_min_score=0.0,
        ),
        qdrant_client=qdrant,
        chat_model=model,
        embeddings=embeddings,
        cwe_evidence=Provider(),  # type: ignore[arg-type]
    )
    try:
        with TestClient(app) as client:
            response = client.post("/v1/knowledge/query", json={"question": question})
        assert response.status_code == 200, response.text
        assert requested == [("CWE-918",)]
        assert response.json()["intent"] == "rag"
        assert response.json()["sources"][0]["source_url"] == source_url
    finally:
        qdrant.close()


def test_empty_openai_key_does_not_construct_provider_adapters() -> None:
    app = create_app(
        Settings(
            database_url="sqlite://",
            intelligence_database_url="sqlite://",
            openai_api_key=SecretStr(""),
        )
    )

    assert app.state.knowledge_service is None
