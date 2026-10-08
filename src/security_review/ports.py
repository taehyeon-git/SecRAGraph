"""Infrastructure-independent application ports."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from security_review.domain.models import ScanReport
from security_review.intelligence.models import DocumentChunk, QueryResult


class ReportRepositoryError(RuntimeError):
    """Persistence failure safe to map at application boundaries."""


class IntelligenceError(RuntimeError):
    """Base error exposed by provider-independent intelligence boundaries."""


class IntelligenceConfigurationError(IntelligenceError):
    """An intelligence capability is disabled by missing or invalid configuration."""

    def __init__(self, reason: str, *, capability: str | None = None) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(reason)


class IntelligenceUnavailableError(IntelligenceError):
    """An enabled external intelligence dependency is temporarily unavailable."""

    def __init__(self, capability: str, reason: str) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(f"{capability}: {reason}")


class ReportRepository(Protocol):
    """Persist and retrieve canonical scan reports."""

    def save(self, report: ScanReport) -> None: ...

    def get(self, scan_id: UUID) -> ScanReport | None: ...


class ChatModel(Protocol):
    """Generate text without exposing a provider SDK to application code."""

    def complete(self, system: str, user: str) -> str: ...


class EmbeddingModel(Protocol):
    """Create fixed-width embedding vectors for ordered input text."""

    @property
    def dimension(self) -> int: ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SecurityKnowledgeRepository(Protocol):
    """Execute an already-validated query through a read-only connection."""

    def execute_readonly(self, sql: str) -> QueryResult: ...


class SecurityDocumentRetriever(Protocol):
    """Retrieve bounded document evidence for a security question."""

    def search(self, query: str, limit: int = 5) -> tuple[DocumentChunk, ...]: ...
