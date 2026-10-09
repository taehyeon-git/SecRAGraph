"""Contract tests for the keyless RAG fixture and its case manifest."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from security_review.evaluation import offline_rag
from security_review.evaluation.offline_rag import (
    TokenHashEmbeddingModel,
    build_offline_retriever,
    load_rag_cases,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GUIDE = REPOSITORY_ROOT / "data/knowledge/secragraph-security-guidelines.md"
CASES = REPOSITORY_ROOT / "data/evaluation/rag_cases.json"


def _case_payload() -> dict[str, object]:
    return {
        "case_id": "direct_parameterized_queries",
        "question": "How should application data be used in SQL queries?",
        "route": "rag",
        "max_rag_attempts": 2,
        "expected_completed_nodes": [
            "classify_intent",
            "vector_search",
            "evaluate_vector_results",
            "generate_grounded_answer",
        ],
        "expected_retrieved_section": "Injection-resistant data access",
        "expected_cited_section": "Injection-resistant data access",
        "expected_outcome": "answer",
        "rewrite_query": None,
        "expected_failure_stage": None,
    }


def _cosine(left: list[float], right: list[float]) -> float:
    numerator = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return numerator / (left_norm * right_norm)


def test_token_hash_vectors_are_deterministic_normalized_and_fixed_width() -> None:
    model = TokenHashEmbeddingModel()

    vectors = model.embed(["ＳＥＣＲＥＴＳ and credentials", "ＳＥＣＲＥＴＳ and credentials"])
    equivalent = TokenHashEmbeddingModel().embed(["secrets credentials"])[0]

    assert model.dimension == 512
    assert vectors[0] == vectors[1] == equivalent
    assert len(vectors[0]) == 512
    assert all(math.isfinite(value) and value >= 0 for value in vectors[0])


def test_shared_security_terms_rank_above_unrelated_terms() -> None:
    model = TokenHashEmbeddingModel()
    query, relevant, unrelated = model.embed(
        [
            "revoke rotate exposed secret credentials",
            "rotate exposed credentials and revoke secret",
            "orbital telemetry lunar mining",
        ]
    )

    assert _cosine(query, relevant) > _cosine(query, unrelated)
    assert _cosine(query, relevant) > 0.8


def test_empty_or_tokenless_text_yields_finite_bounded_vectors() -> None:
    model = TokenHashEmbeddingModel()

    assert model.embed(["", "?!", "the and or"]) == [[0.0] * 512] * 3
    with pytest.raises(ValueError):
        TokenHashEmbeddingModel(dimension=0)


def test_local_qdrant_replacement_and_search_retrieve_bundled_section() -> None:
    client, retriever, chunks = build_offline_retriever(GUIDE)
    try:
        assert isinstance(client, QdrantClient)
        assert len(chunks) > 1
        collections = client.get_collections().collections
        assert len(collections) == 1
        assert client.count(collection_name=collections[0].name).count == len(chunks)

        results = retriever.search("parameterized SQL queries bind application values", limit=5)

        assert results
        assert results[0].section == "Injection-resistant data access"
        assert results[0].title == "SecRAGraph Secure Engineering Guidelines"
        assert results[0].id in {str(chunk.id) for chunk in chunks}
    finally:
        client.close()


def test_bundled_manifest_has_four_labeled_rag_paths() -> None:
    cases = load_rag_cases(CASES)

    assert [case.case_id for case in cases] == [
        "direct_parameterized_queries",
        "rewrite_then_secret_rotation",
        "abstain_without_evidence",
        "reject_forged_citation",
    ]
    assert [case.expected_outcome for case in cases] == [
        "answer",
        "answer",
        "abstain",
        "invalid_source_citation",
    ]
    assert all(case.route == "rag" and case.max_rag_attempts == 2 for case in cases)
    assert "generate_grounded_answer" not in cases[-1].expected_completed_nodes
    assert cases[-1].expected_failure_stage == "grounded_answer_validation"


def test_bundled_case_queries_exercise_labeled_retrieval_paths() -> None:
    direct, rewritten, abstain, forged = load_rag_cases(CASES)
    client, retriever, _ = build_offline_retriever(GUIDE)
    try:
        assert retriever.search(direct.question)[0].section == direct.expected_retrieved_section
        assert retriever.search(rewritten.question) == ()
        assert rewritten.rewrite_query is not None
        assert (
            retriever.search(rewritten.rewrite_query)[0].section
            == rewritten.expected_retrieved_section
        )
        assert retriever.search(abstain.question) == ()
        assert abstain.rewrite_query is not None
        assert retriever.search(abstain.rewrite_query) == ()
        assert retriever.search(forged.question)[0].section == forged.expected_retrieved_section
    finally:
        client.close()


@pytest.mark.parametrize(
    "invalid_case",
    [
        {"route": "general"},
        {"max_rag_attempts": 3},
        {"question": "x" * 2_001},
    ],
)
def test_invalid_case_fails_before_qdrant_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_case: dict[str, object],
) -> None:
    case = _case_payload()
    case.update(invalid_case)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
    monkeypatch.setattr(
        offline_rag,
        "QdrantClient",
        lambda *args, **kwargs: pytest.fail("Qdrant must not be created for invalid cases"),
    )

    with pytest.raises(ValueError):
        load_rag_cases(path)


def test_duplicate_case_ids_fail_before_qdrant_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps({"cases": [_case_payload(), _case_payload()]}), encoding="utf-8")
    monkeypatch.setattr(
        offline_rag,
        "QdrantClient",
        lambda *args, **kwargs: pytest.fail("Qdrant must not be created for duplicate IDs"),
    )

    with pytest.raises(ValueError, match="duplicate"):
        load_rag_cases(path)


def test_malformed_json_fails_before_qdrant_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "malformed.json"
    path.write_text("{broken", encoding="utf-8")
    monkeypatch.setattr(
        offline_rag,
        "QdrantClient",
        lambda *args, **kwargs: pytest.fail("Qdrant must not be created for invalid JSON"),
    )

    with pytest.raises(ValueError):
        load_rag_cases(path)
