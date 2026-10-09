"""Deterministic local retrieval and actual graph-contract evaluation."""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import unicodedata
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import cast

from pydantic import ValidationError
from qdrant_client import QdrantClient

from security_review.evaluation.rag_models import (
    CitedEvidence,
    RagCase,
    RagCaseChecks,
    RagCaseResult,
    RagEvaluation,
    RagMetric,
    RagMetrics,
    RagNode,
)
from security_review.intelligence.fakes import FakeKnowledgeRepository
from security_review.intelligence.ingestion import (
    MAX_DOCUMENT_BYTES,
    DocumentChunkInput,
    DocumentIngestionError,
    chunk_documents,
    load_knowledge_documents,
)
from security_review.intelligence.models import DocumentChunk
from security_review.intelligence.qdrant_retriever import (
    QdrantDocumentRetriever,
    bootstrap_collection,
)
from security_review.intelligence.text2sql import Text2SqlService
from security_review.orchestrator.knowledge_graph import (
    KnowledgeServices,
    KnowledgeWorkflowError,
    build_knowledge_graph,
    knowledge_answer_from_state,
)
from security_review.orchestrator.state import KnowledgeAnswer, KnowledgeState
from security_review.ports import ChatModel

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
_EMBEDDING_ALGORITHM_VERSION = "token-hash-v1"
_GROUNDED_SYSTEM_PREFIX = "Answer only from the retrieved evidence"
_STATE_FIELDS = frozenset({"intent", "attempt", "query", "chunks", "answer", "sources", "warnings"})
_RAG_NODES = frozenset(
    {
        "classify_intent",
        "vector_search",
        "evaluate_vector_results",
        "rewrite_query",
        "generate_grounded_answer",
    }
)
_SOURCE_FILES = (
    "src/security_review/evaluation/offline_rag.py",
    "src/security_review/evaluation/rag_models.py",
    "src/security_review/orchestrator/knowledge_graph.py",
    "src/security_review/intelligence/ingestion.py",
    "src/security_review/intelligence/qdrant_retriever.py",
)
_CITATION = re.compile(r"\[source:([^\]\r\n]+)\]")


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

    return _parse_rag_cases(_read_manifest_bytes(path))


def _read_manifest_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ValueError("RAG case manifest exceeds the size limit")
    return raw


def _parse_rag_cases(raw: bytes) -> tuple[RagCase, ...]:
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


class _OfflineChatModel:
    """Deterministic adapter driven by graph prompts and their evidence."""

    def __init__(self, case: RagCase) -> None:
        self._case = case

    def complete(self, system: str, user: str) -> str:
        if system.startswith("Classify one security question"):
            return "rag"
        if system.startswith("Rewrite a security-document search query"):
            if self._case.rewrite_query is None:
                raise AssertionError("unexpected RAG rewrite")
            return self._case.rewrite_query
        if system.startswith(_GROUNDED_SYSTEM_PREFIX):
            if not user.startswith("UNTRUSTED_DATA_JSON\n"):
                raise AssertionError("missing grounded evidence payload")
            payload = json.loads(user.removeprefix("UNTRUSTED_DATA_JSON\n"))
            evidence = payload.get("retrieved_evidence")
            if not isinstance(evidence, list) or not evidence:
                raise AssertionError("missing grounded evidence")
            top = evidence[0]
            if not isinstance(top, dict) or not isinstance(top.get("id"), str):
                raise AssertionError("invalid grounded evidence")
            if self._case.adapter_fault == "forged_citation":
                return "Unsupported citation [source:forged-offline-source]"
            text = top.get("text")
            if not isinstance(text, str) or not text.strip():
                raise AssertionError("empty grounded evidence")
            sentence = re.split(r"(?<=[.!?])\s+", text.strip(), maxsplit=1)[0][:180].strip()
            return f"{sentence} [source:{top['id']}]"
        raise AssertionError("unexpected non-RAG model prompt")


class _ObservedChatModel:
    """Record only the attempted grounded response if the graph rejects it."""

    def __init__(self, delegate: ChatModel) -> None:
        self._delegate = delegate
        self.last_grounded_answer: str | None = None

    def complete(self, system: str, user: str) -> str:
        response = self._delegate.complete(system, user)
        if system.startswith(_GROUNDED_SYSTEM_PREFIX):
            self.last_grounded_answer = response
        return response


def run_rag_evaluation(cases_path: Path, document_path: Path) -> RagEvaluation:
    """Replay fixed cases through a fresh graph and local Qdrant corpus."""

    manifest_bytes = _read_manifest_bytes(cases_path)
    cases = _parse_rag_cases(manifest_bytes)
    _precheck_corpus_file(document_path)
    client, retriever, chunks = build_offline_retriever(document_path)
    try:
        results = tuple(_evaluate_case(case, retriever) for case in cases)
    finally:
        client.close()
    root = Path(__file__).resolve().parents[3]
    git_revision, git_dirty = _git_identity(root)
    return RagEvaluation(
        cases=results,
        metrics=_summarize_metrics(results),
        manifest_sha256=sha256(manifest_bytes, usedforsecurity=False).hexdigest(),
        corpus_sha256=_chunk_corpus_digest(chunks),
        embedding_algorithm_version=_EMBEDDING_ALGORITHM_VERSION,
        git_revision=git_revision,
        git_dirty=git_dirty,
        source_fingerprint=_source_fingerprint(root),
        passed=all(result.passed for result in results),
    )


def _precheck_corpus_file(path: Path) -> None:
    if not path.is_file():
        return
    if path.is_symlink():
        raise DocumentIngestionError("linked_path_not_allowed")
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise DocumentIngestionError("document_too_large", path.name)
    with path.open("rb") as handle:
        raw = handle.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise DocumentIngestionError("document_too_large", path.name)


def _evaluate_case(case: RagCase, retriever: QdrantDocumentRetriever) -> RagCaseResult:
    model = _ObservedChatModel(_OfflineChatModel(case))
    text2sql = Text2SqlService(
        sql_model=model,
        answer_model=model,
        repository=FakeKnowledgeRepository.empty(),
        max_attempts=1,
        row_limit=1,
    )
    graph = build_knowledge_graph(
        KnowledgeServices(
            chat_model=model,
            text2sql=text2sql,
            retriever=retriever,
            max_rag_attempts=case.max_rag_attempts,
        )
    )
    merged: dict[str, object] = {"question": case.question}
    completed: list[RagNode] = []
    search_queries: list[str] = []
    error: str | None = None
    failure_stage: str | None = None
    answer: KnowledgeAnswer | None = None
    try:
        for event in graph.stream({"question": case.question}, stream_mode="updates"):
            for node, update in event.items():
                if node not in _RAG_NODES or (update is not None and not isinstance(update, dict)):
                    raise AssertionError("unexpected graph update")
                completed.append(cast(RagNode, node))
                if isinstance(update, dict):
                    merged.update(
                        {key: value for key, value in update.items() if key in _STATE_FIELDS}
                    )
                if node == "vector_search":
                    query = merged.get("query")
                    if isinstance(query, str):
                        search_queries.append(query[:200])
        answer = knowledge_answer_from_state(cast(KnowledgeState, merged))
    except KnowledgeWorkflowError as caught:
        error = caught.reason
        failure_stage = (
            "grounded_answer_validation"
            if completed and completed[-1] == "evaluate_vector_results" and merged.get("chunks")
            else "graph_execution"
        )
    except AssertionError:
        error = "unexpected_route_or_prompt"
        failure_stage = "graph_execution"

    retrieved_chunks = cast(tuple[DocumentChunk, ...], merged.get("chunks", ()))
    retrieved = tuple(chunk.to_source_reference() for chunk in retrieved_chunks)
    retrieved_by_id = {item.id: item for item in retrieved}
    chunks_by_id = {chunk.id: chunk for chunk in retrieved_chunks}
    raw_cited_answer = answer.answer if answer is not None else model.last_grounded_answer or ""
    cited_ids = tuple(dict.fromkeys(_CITATION.findall(raw_cited_answer)))
    cited_evidence = (
        tuple(
            CitedEvidence(
                id=source.id,
                title=source.title,
                source_url=source.source_url,
                page=source.page,
                section=source.section,
                score=chunk.score,
                excerpt=_bounded_excerpt(chunk.text),
            )
            for source in answer.sources
            if (chunk := chunks_by_id.get(source.id)) is not None
        )
        if answer is not None
        else ()
    )
    actual_outcome = (
        "invalid_source_citation"
        if error == "invalid_source_citation"
        else "error"
        if error is not None
        else "abstain"
        if answer is not None and "insufficient_evidence" in answer.warnings
        else "answer"
    )
    checks = RagCaseChecks(
        path_match=tuple(completed) == case.expected_completed_nodes,
        retrieval_hit_at_k=(
            any(item.section == case.expected_retrieved_section for item in retrieved)
            if case.expected_retrieved_section is not None
            else None
        ),
        cited_section_correctness=(
            bool(cited_evidence)
            and all(item.section == case.expected_cited_section for item in cited_evidence)
            if case.expected_outcome == "answer"
            else None
        ),
        citation_id_validity=(
            bool(cited_ids) and all(identifier in retrieved_by_id for identifier in cited_ids)
            if case.expected_outcome == "answer"
            else None
        ),
        source_alignment=(
            answer is not None
            and tuple(source.id for source in answer.sources) == cited_ids
            and all(source == retrieved_by_id.get(source.id) for source in answer.sources)
            and len(cited_evidence) == len(cited_ids)
            if case.expected_outcome == "answer"
            else None
        ),
        abstention_success=(
            answer is not None
            and answer.sources == ()
            and "insufficient_evidence" in answer.warnings
            and answer.attempts == case.max_rag_attempts
            if case.expected_outcome == "abstain"
            else None
        ),
        outcome_match=actual_outcome == case.expected_outcome,
        failure_stage_match=failure_stage == case.expected_failure_stage,
    )
    return RagCaseResult(
        case_id=case.case_id,
        expected_completed_nodes=case.expected_completed_nodes,
        completed_nodes=tuple(completed),
        expected_failure_stage=case.expected_failure_stage,
        failure_stage=failure_stage,
        expected_outcome=case.expected_outcome,
        actual_outcome=actual_outcome,
        expected_retrieved_section=case.expected_retrieved_section,
        expected_cited_section=case.expected_cited_section,
        attempts=answer.attempts if answer is not None else cast(int, merged.get("attempt", 0)),
        search_queries=tuple(search_queries),
        retrieved=retrieved,
        cited_evidence=cited_evidence,
        cited_ids=cited_ids,
        answer=answer.answer if answer is not None else None,
        warnings=answer.warnings
        if answer is not None
        else cast(tuple[str, ...], merged.get("warnings", ())),
        error=error,
        checks=checks,
        passed=all(value is not False for value in checks.model_dump().values()),
    )


def _bounded_excerpt(text: str) -> str:
    normalized = " ".join(text.split())
    return normalized if len(normalized) <= 240 else normalized[:239].rstrip() + "…"


def _summarize_metrics(results: tuple[RagCaseResult, ...]) -> RagMetrics:
    def metric(name: str) -> RagMetric:
        applicable = [getattr(result.checks, name) for result in results]
        checked = [value for value in applicable if value is not None]
        denominator = len(checked)
        numerator = sum(value is True for value in checked)
        return RagMetric(
            numerator=numerator,
            denominator=denominator,
            not_applicable=len(results) - denominator,
            value=numerator / denominator if denominator else None,
        )

    return RagMetrics(
        path_match=metric("path_match"),
        retrieval_hit_at_k=metric("retrieval_hit_at_k"),
        cited_section_correctness=metric("cited_section_correctness"),
        citation_id_validity=metric("citation_id_validity"),
        source_alignment=metric("source_alignment"),
        abstention_success=metric("abstention_success"),
    )


def _chunk_corpus_digest(chunks: tuple[DocumentChunkInput, ...]) -> str:
    digest = sha256(usedforsecurity=False)
    digest.update(b"indexed-chunks-v1\n")
    for chunk in chunks:
        record = json.dumps(
            chunk.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest.update(record.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _source_fingerprint(root: Path) -> str:
    digest = sha256(usedforsecurity=False)
    for name in _SOURCE_FILES:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update((root / name).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _git_identity(root: Path) -> tuple[str, bool]:
    git_executable = shutil.which("git")
    if git_executable is None:
        return "unavailable", True
    try:
        # Only the resolved executable and fixed arguments reach these calls; shell is disabled.
        revision = subprocess.run(  # noqa: S603
            [git_executable, "rev-parse", "--verify", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(  # noqa: S603
            [git_executable, "status", "--porcelain", "--untracked-files=normal"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "unavailable", True
    return revision, bool(status.strip())
