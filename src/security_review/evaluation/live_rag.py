"""Opt-in observation of provider-backed RAG workflow behavior."""

from __future__ import annotations

import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from qdrant_client import QdrantClient

from security_review.evaluation.offline_rag import (
    _chunk_corpus_digest,
    _evaluate_case,
    _parse_rag_cases,
    _read_manifest_bytes,
)
from security_review.evaluation.rag_models import RagCase
from security_review.intelligence.ingestion import chunk_documents, load_knowledge_documents
from security_review.intelligence.qdrant_retriever import (
    QdrantDocumentRetriever,
    bootstrap_collection,
)
from security_review.ports import ChatModel, EmbeddingModel

_COLLECTION = "live_rag_evidence"
_MAX_LIVE_CASES = 4


class LiveMetric(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)


class LiveCaseResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    actual_outcome: str
    route_match: bool | None
    retrieval_hit: bool | None
    citation_valid: bool | None
    abstention_success: bool | None
    answer_sha256: str | None = None
    latency_ms: int = Field(ge=0)
    error: str | None = None
    factual_support: Literal["requires_human_review"] = "requires_human_review"


class LiveEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: Literal["opt_in_live_provider"] = "opt_in_live_provider"
    chat_model_id: str = Field(min_length=1, max_length=200)
    embedding_model_id: str = Field(min_length=1, max_length=200)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases: tuple[LiveCaseResult, ...]
    metrics: dict[str, LiveMetric]
    provider_errors: int = Field(ge=0)
    factual_support_claim: Literal["not_machine_scored"] = "not_machine_scored"


def _metric(cases: tuple[LiveCaseResult, ...], field: str) -> LiveMetric:
    values = [getattr(case, field) for case in cases]
    checked = [value for value in values if value is not None]
    return LiveMetric(numerator=sum(value is True for value in checked), denominator=len(checked))


def run_live_evaluation(
    cases_path: Path,
    document_path: Path,
    *,
    chat_factory: Callable[[RagCase], ChatModel],
    embeddings: EmbeddingModel,
    chat_model_id: str,
    embedding_model_id: str,
) -> LiveEvaluation:
    """Run bounded graph cases with injected adapters and a fresh local Qdrant."""

    raw_manifest = _read_manifest_bytes(cases_path)
    cases = tuple(case for case in _parse_rag_cases(raw_manifest) if case.adapter_fault is None)
    if not 1 <= len(cases) <= _MAX_LIVE_CASES:
        raise ValueError("live RAG case count must be between one and four")
    documents = load_knowledge_documents(document_path)
    chunks = chunk_documents(documents, chunk_size=120, overlap=0)
    client = QdrantClient(location=":memory:")
    try:
        bootstrap_collection(client, _COLLECTION, embeddings.dimension)
        retriever = QdrantDocumentRetriever(client, embeddings, _COLLECTION, min_score=0.18)
        retriever.replace_documents(chunks)
        observed: list[LiveCaseResult] = []
        for case in cases:
            started = time.perf_counter()
            try:
                result = _evaluate_case(case, retriever, chat_factory(case))
                error = result.error
                observed.append(
                    LiveCaseResult(
                        case_id=case.case_id,
                        actual_outcome=result.actual_outcome,
                        route_match=result.checks.path_match if error is None else None,
                        retrieval_hit=result.checks.retrieval_hit_at_k if error is None else None,
                        citation_valid=result.checks.citation_id_validity
                        if error is None
                        else None,
                        abstention_success=(
                            result.checks.abstention_success if error is None else None
                        ),
                        answer_sha256=(
                            sha256(result.answer.encode("utf-8")).hexdigest()
                            if result.answer is not None
                            else None
                        ),
                        latency_ms=max(0, round((time.perf_counter() - started) * 1_000)),
                        error=error,
                    )
                )
            except Exception:  # A provider may fail per case; its raw error must not be logged.
                observed.append(
                    LiveCaseResult(
                        case_id=case.case_id,
                        actual_outcome="error",
                        route_match=None,
                        retrieval_hit=None,
                        citation_valid=None,
                        abstention_success=None,
                        latency_ms=max(0, round((time.perf_counter() - started) * 1_000)),
                        error="provider_or_graph_error",
                    )
                )
    finally:
        client.close()
    results = tuple(observed)
    return LiveEvaluation(
        chat_model_id=chat_model_id,
        embedding_model_id=embedding_model_id,
        manifest_sha256=sha256(raw_manifest).hexdigest(),
        corpus_sha256=_chunk_corpus_digest(chunks),
        cases=results,
        metrics={
            "route": _metric(results, "route_match"),
            "retrieval": _metric(results, "retrieval_hit"),
            "citation": _metric(results, "citation_valid"),
            "abstention": _metric(results, "abstention_success"),
        },
        provider_errors=sum(case.error is not None for case in results),
    )
