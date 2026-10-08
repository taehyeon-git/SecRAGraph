"""Real Qdrant contract checks with deterministic local embeddings."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from qdrant_client import QdrantClient
from qdrant_client.http import models

from security_review.intelligence.fakes import FakeEmbeddingModel
from security_review.intelligence.ingestion import (
    KnowledgeDocument,
    chunk_document,
    load_knowledge_documents,
)
from security_review.intelligence.qdrant_retriever import (
    CollectionConfigurationError,
    QdrantDocumentRetriever,
)

pytestmark = pytest.mark.integration


def qdrant_url() -> str:
    return os.getenv("SECRAGRAPH_TEST_QDRANT_URL", "http://127.0.0.1:56333")


def test_original_security_guide_can_be_ingested_and_retrieved() -> None:
    client = QdrantClient(url=qdrant_url(), timeout=5)
    collection = f"secragraph-test-{uuid4().hex}"
    created = False
    try:
        document = load_knowledge_documents(
            Path("data/knowledge/secragraph-security-guidelines.md")
        )[0]
        chunks = chunk_document(document, chunk_size=80, overlap=10)
        target = next(chunk for chunk in chunks if "parameterized queries" in chunk.text)
        vectors = {
            chunk.text: ([1.0, 0.0, 0.0] if chunk.id == target.id else [0.0, 1.0, 0.0])
            for chunk in chunks
        }
        vectors["How should SQL input be handled?"] = [1.0, 0.0, 0.0]
        retriever = QdrantDocumentRetriever(
            client,
            FakeEmbeddingModel(dimension=3, vectors=vectors),
            collection,
            min_score=0.5,
        )

        retriever.ensure_collection()
        created = True
        assert retriever.upsert(chunks) == len(chunks)
        result = retriever.search("How should SQL input be handled?", limit=3)

        assert result
        assert result[0].id == str(target.id)
        assert "parameterized queries" in result[0].text
        assert result[0].title == "SecRAGraph Secure Engineering Guidelines"
        assert result[0].section == "Injection-resistant data access"
    finally:
        if created:
            client.delete_collection(collection)
        client.close()


def test_real_collection_dimension_mismatch_is_explicit() -> None:
    client = QdrantClient(url=qdrant_url(), timeout=5)
    collection = f"secragraph-mismatch-{uuid4().hex}"
    created = False
    try:
        client.create_collection(
            collection_name=collection,
            vectors_config=models.VectorParams(size=2, distance=models.Distance.COSINE),
        )
        created = True
        retriever = QdrantDocumentRetriever(
            client,
            FakeEmbeddingModel(dimension=3),
            collection,
        )

        with pytest.raises(CollectionConfigurationError, match="2.*3"):
            retriever.check_ready()
    finally:
        if created:
            client.delete_collection(collection)
        client.close()


def test_replacing_a_changed_document_removes_stale_qdrant_points() -> None:
    client = QdrantClient(url=qdrant_url(), timeout=5)
    collection = f"secragraph-replace-{uuid4().hex}"
    created = False
    try:
        old_chunks = chunk_document(
            KnowledgeDocument(
                source_path="same.md",
                title="Same guide",
                text="old evidence that must disappear",
            ),
            chunk_size=20,
            overlap=0,
        )
        new_chunks = chunk_document(
            KnowledgeDocument(
                source_path="same.md",
                title="Same guide",
                text="new evidence that replaces it",
            ),
            chunk_size=20,
            overlap=0,
        )
        embeddings = FakeEmbeddingModel(
            dimension=3,
            vectors={
                old_chunks[0].text: [1.0, 0.0, 0.0],
                new_chunks[0].text: [1.0, 0.0, 0.0],
            },
        )
        retriever = QdrantDocumentRetriever(client, embeddings, collection)
        retriever.ensure_collection()
        created = True

        retriever.replace_documents(old_chunks)
        retriever.replace_documents(new_chunks)
        points, _ = client.scroll(
            collection_name=collection,
            limit=10,
            with_payload=True,
            with_vectors=False,
        )

        assert [point.id for point in points] == [str(new_chunks[0].id)]
        assert [point.payload["text"] for point in points if point.payload] == [
            "new evidence that replaces it"
        ]
    finally:
        if created:
            client.delete_collection(collection)
        client.close()
