"""Managed-corpus reconciliation must never erase other or untagged points."""

from __future__ import annotations

import pytest
from qdrant_client import QdrantClient

from security_review.intelligence.fakes import FakeEmbeddingModel
from security_review.intelligence.ingestion import KnowledgeDocument, chunk_document
from security_review.intelligence.qdrant_retriever import (
    QdrantDocumentRetriever,
    bootstrap_collection,
)
from security_review.ports import IntelligenceUnavailableError


def _chunks(
    corpus_id: str | None,
    *,
    text: str = "alpha beta gamma delta",
    source_path: str = "guide.md",
    source_url: str | None = None,
    chunk_size: int = 20,
):
    document = KnowledgeDocument(
        source_path=source_path,
        title="Guide",
        text=text,
        source_url=source_url,
        corpus_id=corpus_id,
    )
    return chunk_document(document, chunk_size, 0)


def _all_points(client: QdrantClient) -> list[object]:
    points, offset = client.scroll("test-corpus", limit=100, with_payload=True)
    assert offset is None
    return points


@pytest.fixture
def store() -> tuple[QdrantClient, QdrantDocumentRetriever]:
    client = QdrantClient(location=":memory:")
    bootstrap_collection(client, "test-corpus", 3)
    retriever = QdrantDocumentRetriever(client, FakeEmbeddingModel(3), "test-corpus")
    yield client, retriever
    client.close()


def test_sync_replaces_shrunk_document_without_touching_other_corpora_or_legacy(
    store: tuple[QdrantClient, QdrantDocumentRetriever],
) -> None:
    client, retriever = store
    old = _chunks("team-a", text="alpha beta gamma delta", chunk_size=2)
    other = _chunks("team-b", text="other corpus")
    legacy = _chunks(None, text="legacy content")
    retriever.replace_documents((*old, *other, *legacy))
    new = _chunks("team-a", text="alpha beta", chunk_size=2)

    preview = retriever.sync_corpus("team-a", new, apply=False)
    assert not preview.applied
    assert len(_all_points(client)) == 4

    applied = retriever.sync_corpus("team-a", new, apply=True)
    assert applied.applied
    points = _all_points(client)
    assert {str(point.id) for point in points} == {
        str(chunk.id) for chunk in (*new, *other, *legacy)
    }
    assert all(
        point.payload.get("corpus_id") == "team-a"
        for point in points
        if str(point.id) == str(new[0].id)
    )


def test_sync_removes_missing_and_changed_identity_only_in_selected_corpus(
    store: tuple[QdrantClient, QdrantDocumentRetriever],
) -> None:
    client, retriever = store
    removed = _chunks("team-a", source_path="removed.md")
    renamed_identity = _chunks("team-a", source_url="https://example.com/old")
    other = _chunks("team-b", source_path="removed.md")
    retriever.replace_documents((*removed, *renamed_identity, *other))
    desired = _chunks("team-a", source_url="https://example.com/new")

    preview = retriever.preview_corpus_sync("team-a", {desired[0].document_id})
    assert set(preview.stale_document_ids) == {
        removed[0].document_id,
        renamed_identity[0].document_id,
    }
    retriever.sync_corpus("team-a", desired, apply=True)

    assert {str(point.id) for point in _all_points(client)} == {
        str(desired[0].id),
        str(other[0].id),
    }


def test_empty_apply_requires_explicit_allow_empty_and_preserves_other_corpora(
    store: tuple[QdrantClient, QdrantDocumentRetriever],
) -> None:
    client, retriever = store
    selected = _chunks("team-a")
    other = _chunks("team-b")
    retriever.replace_documents((*selected, *other))

    assert len(retriever.sync_corpus("team-a", (), apply=False).stale_document_ids) == 1
    with pytest.raises(ValueError, match="allow_empty"):
        retriever.sync_corpus("team-a", (), apply=True)
    retriever.sync_corpus("team-a", (), apply=True, allow_empty=True)

    assert {str(point.id) for point in _all_points(client)} == {str(other[0].id)}


def test_mixed_or_untagged_input_is_rejected_before_writes(
    store: tuple[QdrantClient, QdrantDocumentRetriever],
) -> None:
    client, retriever = store
    with pytest.raises(ValueError, match="corpus"):
        retriever.sync_corpus("team-a", (*_chunks("team-a"), *_chunks("team-b")), apply=True)
    with pytest.raises(ValueError, match="corpus"):
        retriever.sync_corpus("team-a", _chunks(None), apply=True)
    assert _all_points(client) == []


def test_upsert_failure_does_not_delete_absent_documents(
    store: tuple[QdrantClient, QdrantDocumentRetriever],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, retriever = store
    absent = _chunks("team-a", source_path="absent.md")
    retriever.replace_documents(absent)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic provider fault")

    monkeypatch.setattr(client, "upsert", fail)
    with pytest.raises(IntelligenceUnavailableError, match="upsert_failed"):
        retriever.sync_corpus("team-a", _chunks("team-a"), apply=True)
    assert {str(point.id) for point in _all_points(client)} == {str(absent[0].id)}
