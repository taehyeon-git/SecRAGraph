"""Validated labels for the fixed offline RAG workflow cases."""

from __future__ import annotations

from typing import Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from security_review.domain.models import SourceReference
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
    adapter_fault: Literal["forged_citation"] | None = None
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


class CitedEvidence(BaseModel):
    """Only validated cited metadata and a short excerpt, never a full chunk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    title: str
    source_url: str | None = None
    page: int | None = None
    section: str | None = None
    score: float
    excerpt: str = Field(min_length=1, max_length=240)


class RagCaseChecks(BaseModel):
    """Case-level labels; None means the measure does not apply."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path_match: bool
    retrieval_hit_at_k: bool | None
    cited_section_correctness: bool | None
    citation_id_validity: bool | None
    source_alignment: bool | None
    abstention_success: bool | None
    outcome_match: bool
    failure_stage_match: bool


class RagCaseResult(BaseModel):
    """One graph execution with only bounded public diagnostics."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    expected_completed_nodes: tuple[RagNode, ...]
    completed_nodes: tuple[RagNode, ...]
    expected_failure_stage: str | None
    failure_stage: str | None
    expected_outcome: RagOutcome
    actual_outcome: str
    expected_retrieved_section: str | None
    expected_cited_section: str | None
    attempts: int = Field(ge=0)
    search_queries: tuple[str, ...]
    retrieved: tuple[SourceReference, ...]
    cited_evidence: tuple[CitedEvidence, ...]
    cited_ids: tuple[str, ...]
    answer: str | None = None
    warnings: tuple[str, ...] = ()
    error: str | None = None
    checks: RagCaseChecks
    passed: bool


class RagMetric(BaseModel):
    """An explicit ratio and its count of inapplicable cases."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    value: float | None


class RagMetrics(BaseModel):
    """Workflow and evidence-contract scores over their applicable cases."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path_match: RagMetric
    retrieval_hit_at_k: RagMetric
    cited_section_correctness: RagMetric
    citation_id_validity: RagMetric
    source_alignment: RagMetric
    abstention_success: RagMetric


class RagEvaluation(BaseModel):
    """Reproducible local workflow evidence for one fixed manifest and corpus."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cases: tuple[RagCaseResult, ...]
    metrics: RagMetrics
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 of canonical indexed chunk records, not raw source file bytes",
    )
    corpus_digest_kind: Literal["indexed-chunks-v1"] = "indexed-chunks-v1"
    embedding_algorithm_version: str
    git_revision: str
    git_dirty: bool
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    passed: bool
