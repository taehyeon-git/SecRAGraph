"""Real PostgreSQL/Qdrant knowledge flow with deterministic model boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from qdrant_client import QdrantClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.intelligence.fakes import FakeEmbeddingModel
from security_review.intelligence.ingestion import chunk_documents, load_knowledge_documents
from security_review.intelligence.qdrant_retriever import QdrantDocumentRetriever
from security_review.storage.intelligence import import_intelligence_data

pytestmark = pytest.mark.integration


def _database_url() -> str:
    return os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@localhost:55432/secragraph_test",
    )


def _qdrant_url() -> str:
    return os.getenv("SECRAGRAPH_TEST_QDRANT_URL", "http://127.0.0.1:56333")


class DeterministicChat:
    """Decide from prompts while preserving real SQL and retrieval boundaries."""

    def complete(self, system: str, user: str) -> str:
        if system.startswith("Classify one security question"):
            return "text2sql" if "CVE" in user else "rag"
        if system.startswith("Generate exactly one PostgreSQL SELECT"):
            return "SELECT cve_id FROM intel.cve ORDER BY cve_id LIMIT 1"
        if system.startswith("You summarize bounded security-database"):
            payload = json.loads(user.split("\n", 1)[1].rsplit("\n", 1)[0])
            return f"Sample CVE: {payload['rows'][0][0]}"
        if system.startswith("Answer only from the retrieved evidence"):
            payload = json.loads(user.split("\n", 1)[1])
            source = payload["retrieved_evidence"][0]
            return f"Use parameterized queries [source:{source['id']}]."
        raise AssertionError("unexpected chat prompt")


def test_live_text2sql_and_original_markdown_rag_paths() -> None:
    database_url = _database_url()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        import_intelligence_data(engine, Path("data/samples/cwe.csv"), Path("data/samples/cve.csv"))
    finally:
        engine.dispose()

    qdrant = QdrantClient(url=_qdrant_url(), timeout=5)
    collection = f"secragraph-flow-{uuid4().hex}"
    created = False
    try:
        chunks = chunk_documents(
            load_knowledge_documents(Path("data/knowledge/secragraph-security-guidelines.md")),
            350,
            50,
        )
        target = next(chunk for chunk in chunks if "parameterized queries" in chunk.text)
        question = "How should SQL input be handled?"
        vectors = {
            chunk.text: ([1.0, 0.0, 0.0] if chunk.id == target.id else [0.0, 1.0, 0.0])
            for chunk in chunks
        }
        vectors[question] = [1.0, 0.0, 0.0]
        embeddings = FakeEmbeddingModel(dimension=3, vectors=vectors)
        retriever = QdrantDocumentRetriever(qdrant, embeddings, collection, min_score=0.5)
        retriever.ensure_collection()
        created = True
        assert retriever.replace_documents(chunks) == len(chunks)

        reader_url = make_url(database_url).set(
            username="secragraph_text2sql",
            password=os.getenv("SECRAGRAPH_TEST_READER_PASSWORD"),
        )
        app = create_app(
            Settings(
                database_url=database_url,
                intelligence_database_url=reader_url.render_as_string(hide_password=False),
                qdrant_url=_qdrant_url(),
                qdrant_collection=collection,
                qdrant_vector_dimension=3,
                qdrant_min_score=0.5,
                openai_api_key=None,
            ),
            chat_model=DeterministicChat(),
            embeddings=embeddings,
        )
        with TestClient(app) as client:
            readiness = client.get("/health/ready")
            sql = client.post("/v1/knowledge/query", json={"question": "List one CVE"})
            rag = client.post("/v1/knowledge/query", json={"question": question})

        assert readiness.status_code == 200
        assert readiness.json()["dependencies"] == {"postgres": True, "qdrant": True}
        assert sql.status_code == 200, sql.json()
        assert sql.json()["intent"] == "text2sql"
        assert "CVE-" in sql.json()["answer"]
        assert rag.status_code == 200
        assert rag.json()["intent"] == "rag"
        assert rag.json()["sources"][0]["id"] == str(target.id)
        assert "parameterized queries" in rag.json()["answer"]
    finally:
        if created:
            qdrant.delete_collection(collection)
        qdrant.close()
