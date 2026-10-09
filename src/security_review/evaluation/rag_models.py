"""Validated labels for the fixed offline RAG workflow cases."""

from __future__ import annotations

from typing import Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from security_review.orchestrator.knowledge_graph import MAX_QUESTION_CHARACTERS

RagOutcome: TypeAlias = Literal["answer", "abstain", "invalid_source_citation"]
RagNode: TypeAlias = Literal[
    "classify_intent",
    "vector_search",
    "evaluate_vector_results",
    "rewrite_query",
    "generate_grounded_answer",
]


class RagCase(BaseModel):
    """One bounded, labeled RAG path through the real knowledge graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARACTERS)
    route: Literal["rag"]
    max_rag_attempts: Literal[2]
    expected_completed_nodes: tuple[RagNode, ...] = Field(min_length=1, max_length=7)
    expected_retrieved_section: str | None = Field(default=None, max_length=500)
    expected_cited_section: str | None = Field(default=None, max_length=500)
    expected_outcome: RagOutcome
    rewrite_query: str | None = Field(default=None, max_length=MAX_QUESTION_CHARACTERS)
    expected_failure_stage: Literal["grounded_answer_validation"] | None = None

    @field_validator(
        "question",
        "expected_retrieved_section",
        "expected_cited_section",
        "rewrite_query",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("case text must be a string")
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("case text must not be blank or contain NUL")
        return normalized

    @model_validator(mode="after")
    def validate_labels(self) -> Self:
        rewrites = "rewrite_query" in self.expected_completed_nodes
        if rewrites != (self.rewrite_query is not None):
            raise ValueError("rewrite label and completed nodes disagree")
        if self.expected_outcome == "answer":
            if self.expected_cited_section is None or self.expected_failure_stage is not None:
                raise ValueError("answer cases require a cited section and no failure stage")
        elif self.expected_outcome == "abstain":
            if self.expected_cited_section is not None or self.expected_failure_stage is not None:
                raise ValueError("abstention cases cannot cite or fail")
        elif (
            self.expected_cited_section is not None
            or self.expected_failure_stage != "grounded_answer_validation"
            or "generate_grounded_answer" in self.expected_completed_nodes
        ):
            raise ValueError("invalid citation cases must stop before completed generation")
        return self
