"""Production composition must respect missing credentials and owned lifecycles."""

from __future__ import annotations

from fastapi.testclient import TestClient
from pydantic import SecretStr

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.intelligence.fakes import FakeChatModel, FakeEmbeddingModel


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


def test_empty_openai_key_does_not_construct_provider_adapters() -> None:
    app = create_app(
        Settings(
            database_url="sqlite://",
            intelligence_database_url="sqlite://",
            openai_api_key=SecretStr(""),
        )
    )

    assert app.state.knowledge_service is None
