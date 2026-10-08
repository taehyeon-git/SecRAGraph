"""Canonical domain and request schemas exposed by the HTTP API."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from security_review.domain.models import ScanReport
from security_review.orchestrator.knowledge_graph import MAX_QUESTION_CHARACTERS
from security_review.orchestrator.state import KnowledgeAnswer


class KnowledgeQueryRequest(BaseModel):
    """One bounded, normalized security question."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARACTERS)

    @field_validator("question")
    @classmethod
    def reject_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("question must not contain NUL")
        return value


__all__ = ["KnowledgeAnswer", "KnowledgeQueryRequest", "ScanReport"]
