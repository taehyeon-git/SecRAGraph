"""Deterministic test doubles for security-intelligence ports."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from hashlib import shake_256

from security_review.intelligence.models import DocumentChunk, QueryResult


class FakeResponseExhaustedError(RuntimeError):
    """Raised when a scripted fake receives more calls than responses."""


class FakeChatModel:
    """FIFO chat model that records every prompt pair."""

    def __init__(self, responses: Iterable[str | Exception]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if not self._responses:
            raise FakeResponseExhaustedError("no configured response remains")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeEmbeddingModel:
    """Fixed-width embeddings with optional exact vectors by input text."""

    def __init__(
        self,
        dimension: int,
        vectors: Mapping[str, Sequence[float]] | None = None,
        failure: Exception | None = None,
    ) -> None:
        if dimension < 1:
            raise ValueError("dimension must be at least 1")
        configured = {text: list(vector) for text, vector in (vectors or {}).items()}
        for text, vector in configured.items():
            if len(vector) != dimension:
                raise ValueError(
                    f"configured vector for {text!r} does not match dimension {dimension}"
                )
        self._dimension = dimension
        self._vectors = configured
        self._failure = failure
        self.calls: list[tuple[str, ...]] = []

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        batch = tuple(texts)
        self.calls.append(batch)
        if self._failure is not None:
            raise self._failure
        return [list(self._vectors.get(text, self._stable_vector(text))) for text in batch]

    def _stable_vector(self, text: str) -> list[float]:
        raw = shake_256(text.encode("utf-8")).digest(self._dimension * 2)
        return [
            (int.from_bytes(raw[offset : offset + 2], "big") / 32_767.5) - 1.0
            for offset in range(0, len(raw), 2)
        ]


class FakeKnowledgeRepository:
    """Read-only result fake that exposes calls for exact assertions."""

    def __init__(
        self,
        result: QueryResult | None = None,
        failure: Exception | None = None,
    ) -> None:
        self._result = result or QueryResult(columns=(), rows=())
        self._failure = failure
        self.queries: list[str] = []
        self.mutations: list[str] = []

    @classmethod
    def empty(cls) -> FakeKnowledgeRepository:
        return cls(QueryResult(columns=(), rows=()))

    def execute_readonly(self, sql: str) -> QueryResult:
        self.queries.append(sql)
        if re.search(
            r"\b(?:insert|update|delete|drop|alter|create|truncate|copy|grant|revoke)\b",
            sql,
            flags=re.IGNORECASE,
        ):
            self.mutations.append(sql)
            raise AssertionError("read-only fake received mutation SQL")
        if self._failure is not None:
            raise self._failure
        return self._result


class FakeDocumentRetriever:
    """Query-keyed retriever with a mutable fallback for graph scenarios."""

    def __init__(
        self,
        responses: Mapping[str, Sequence[DocumentChunk]] | None = None,
        *,
        results: Sequence[DocumentChunk] = (),
        failure: Exception | None = None,
    ) -> None:
        self._responses = {query: tuple(chunks) for query, chunks in (responses or {}).items()}
        self.results = tuple(results)
        self._failure = failure
        self.calls: list[tuple[str, int]] = []

    def search(self, query: str, limit: int = 5) -> tuple[DocumentChunk, ...]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self.calls.append((query, limit))
        if self._failure is not None:
            raise self._failure
        return self._responses.get(query, self.results)[:limit]
