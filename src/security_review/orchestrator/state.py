"""Typed state and public results for security-knowledge orchestration."""

from __future__ import annotations

from typing import Literal, TypeAlias, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from security_review.domain.models import SourceReference
from security_review.intelligence.models import DocumentChunk
from security_review.intelligence.text2sql import Text2SqlAnswer

KnowledgeIntent: TypeAlias = Literal["general", "text2sql", "rag"]


class KnowledgeState(TypedDict, total=False):
    """State shared only by the explicit nodes in the knowledge graph."""

    question: str
    intent: KnowledgeIntent
    attempt: int
    query: str
    sql_answer: Text2SqlAnswer | None
    chunks: tuple[DocumentChunk, ...]
    answer: str
    sources: tuple[SourceReference, ...]
    warnings: tuple[str, ...]


class KnowledgeAnswer(BaseModel):
    """Provider-independent answer returned to API and CLI adapters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent: KnowledgeIntent
    answer: str = Field(min_length=1, max_length=20_000)
    attempts: int = Field(ge=1, le=100)
    sources: tuple[SourceReference, ...] = ()
    warnings: tuple[str, ...] = ()
