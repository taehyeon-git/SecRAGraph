"""Deterministic local retrieval from the original bundled security guide."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError
from qdrant_client import QdrantClient

from security_review.evaluation.rag_models import RagCase
from security_review.intelligence.ingestion import (
    DocumentChunkInput,
    chunk_documents,
    load_knowledge_documents,
)
from security_review.intelligence.qdrant_retriever import (
    QdrantDocumentRetriever,
    bootstrap_collection,
)

_WORD = re.compile(r"\w+", flags=re.UNICODE)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "how",
        "in",
        "is",
        "of",
        "on",
        "or",
        "the",
        "to",
        "what",
        "when",
        "why",
        "with",
    }
)
_COLLECTION = "offline_rag_evidence"
_MAX_MANIFEST_BYTES = 128_000
_MAX_CASES = 32


class TokenHashEmbeddingModel:
    """Nonnegative normalized token counts for repeatable local cosine search."""

    def __init__(self, dimension: int = 512) -> None:
        if type(dimension) is not int or not 1 <= dimension <= 4_096:
            raise ValueError("dimension must be between 1 and 4096")
        self.dimension = dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            buckets = [0.0] * self.dimension
            for token in _WORD.findall(unicodedata.normalize("NFKC", text).casefold()):
                if token in _STOPWORDS:
                    continue
                digest = sha256(token.encode("utf-8"), usedforsecurity=False).digest()
                bucket = int.from_bytes(digest[:8], "big") % self.dimension
                buckets[bucket] += 1.0
            norm = math.sqrt(sum(value * value for value in buckets))
            vectors.append([value / norm for value in buckets] if norm else buckets)
        return vectors


def load_rag_cases(path: Path) -> tuple[RagCase, ...]:
    """Read and validate every fixed case before local retrieval is initialized."""

    with path.open("rb") as handle:
        raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ValueError("RAG case manifest exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid RAG case manifest JSON") from error
    if not isinstance(payload, dict) or set(payload) != {"cases"}:
        raise ValueError("RAG case manifest must contain only a cases list")
    raw_cases = payload["cases"]
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= _MAX_CASES:
        raise ValueError("RAG case count is outside the supported range")
    cases: list[RagCase] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_cases):
        try:
            case = RagCase.model_validate(item)
        except ValidationError as error:
            raise ValueError(f"invalid RAG case at index {index}") from error
        if case.case_id in seen_ids:
            raise ValueError("duplicate RAG case ID")
        seen_ids.add(case.case_id)
        cases.append(case)
    return tuple(cases)


def build_offline_retriever(
    document_path: Path,
) -> tuple[QdrantClient, QdrantDocumentRetriever, tuple[DocumentChunkInput, ...]]:
    """Index validated Markdown in a real, in-memory Qdrant collection."""

    documents = load_knowledge_documents(document_path)
    chunks = chunk_documents(documents, chunk_size=120, overlap=0)
    embeddings = TokenHashEmbeddingModel()
    client = QdrantClient(location=":memory:")
    try:
        bootstrap_collection(client, _COLLECTION, embeddings.dimension)
        retriever = QdrantDocumentRetriever(
            client,
            embeddings,
            _COLLECTION,
            min_score=0.18,
        )
        retriever.replace_documents(chunks)
    except Exception:
        client.close()
        raise
    return client, retriever, chunks
