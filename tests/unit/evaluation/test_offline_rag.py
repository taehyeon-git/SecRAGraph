"""Contract tests for the keyless RAG fixture and its case manifest."""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from security_review.evaluation import offline_rag
from security_review.evaluation.offline_rag import (
    TokenHashEmbeddingModel,
    build_offline_retriever,
    load_rag_cases,
)
from security_review.intelligence.ingestion import MAX_DOCUMENT_BYTES, DocumentIngestionError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GUIDE = REPOSITORY_ROOT / "data/knowledge/secragraph-security-guidelines.md"
CASES = REPOSITORY_ROOT / "data/evaluation/rag_cases.json"


def _git_test_repository(path: Path, git_executable: str) -> str:
    subprocess.run([git_executable, "init", "-q", str(path)], check=True)  # noqa: S603
    (path / "tracked.txt").write_text("original\n", encoding="utf-8")
    subprocess.run(  # noqa: S603
        [git_executable, "-C", str(path), "add", "--", "tracked.txt"], check=True
    )
    subprocess.run(  # noqa: S603
        [
            git_executable,
            "-C",
            str(path),
            "-c",
            "user.name=Offline RAG Test",
            "-c",
            "user.email=offline-rag@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        check=True,
    )
    return subprocess.run(  # noqa: S603
        [git_executable, "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_git_identity_reports_revision_and_tracked_edits(tmp_path: Path) -> None:
    git_executable = shutil.which("git")
    if git_executable is None:
        pytest.skip("Git is unavailable")
    revision = _git_test_repository(tmp_path, git_executable)

    assert offline_rag._git_identity(tmp_path) == (revision, False)

    (tmp_path / "tracked.txt").write_text("edited\n", encoding="utf-8")
    assert offline_rag._git_identity(tmp_path) == (revision, True)


def test_git_identity_disables_fsmonitor_when_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_executable = shutil.which("git")
    if git_executable is None:
        pytest.skip("Git is unavailable")
    revision = _git_test_repository(tmp_path, git_executable)
    real_run = subprocess.run

    def guarded_run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        assert options.get("shell") is False
        if "status" in command:
            assert command[1:4] == ["-c", "core.fsmonitor=false", "status"]
        return real_run(command, **options)

    monkeypatch.setattr(offline_rag.subprocess, "run", guarded_run)

    assert offline_rag._git_identity(tmp_path) == (revision, False)


def test_git_identity_falls_back_without_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(offline_rag.shutil, "which", lambda executable: None)

    assert offline_rag._git_identity(tmp_path) == ("unavailable", True)


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
    assert all(case.adapter_fault is None for case in cases[:3])
    assert cases[-1].adapter_fault == "forged_citation"
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


def _write_cases(tmp_path: Path, cases: list[dict[str, object]]) -> Path:
    path = tmp_path / "cases.json"
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path


def test_real_graph_evaluation_reports_completed_paths_and_bounded_evidence() -> None:
    evaluation = offline_rag.run_rag_evaluation(CASES, GUIDE)
    direct, rewritten, abstained, forged = evaluation.cases

    assert evaluation.passed
    assert [case.case_id for case in evaluation.cases] == [
        "direct_parameterized_queries",
        "rewrite_then_secret_rotation",
        "abstain_without_evidence",
        "reject_forged_citation",
    ]
    assert direct.completed_nodes == (
        "classify_intent",
        "vector_search",
        "evaluate_vector_results",
        "generate_grounded_answer",
    )
    assert rewritten.completed_nodes == (
        "classify_intent",
        "vector_search",
        "evaluate_vector_results",
        "rewrite_query",
        "vector_search",
        "evaluate_vector_results",
        "generate_grounded_answer",
    )
    assert abstained.completed_nodes == (
        "classify_intent",
        "vector_search",
        "evaluate_vector_results",
        "rewrite_query",
        "vector_search",
        "evaluate_vector_results",
    )
    assert forged.completed_nodes == ("classify_intent", "vector_search", "evaluate_vector_results")
    assert [case.attempts for case in evaluation.cases] == [1, 2, 2, 1]
    assert direct.retrieved[0].section == "Injection-resistant data access"
    assert rewritten.retrieved[0].section == "Secrets and credential handling"
    assert rewritten.cited_ids == (rewritten.retrieved[0].id,)
    assert all(
        "text" not in item.model_dump() for case in evaluation.cases for item in case.retrieved
    )
    assert all(
        len(item.excerpt) <= 240 for case in evaluation.cases for item in case.cited_evidence
    )
    assert direct.cited_evidence[0].id == direct.cited_ids[0]
    assert abstained.retrieved == abstained.cited_evidence == abstained.cited_ids == ()
    assert abstained.warnings == ("insufficient_evidence",)
    assert forged.failure_stage == "grounded_answer_validation"
    assert forged.error == "invalid_source_citation"
    assert forged.answer is None
    assert forged.cited_evidence == ()
    assert evaluation.metrics.path_match.model_dump() == {
        "numerator": 4,
        "denominator": 4,
        "not_applicable": 0,
        "value": 1.0,
    }
    assert evaluation.metrics.retrieval_hit_at_k.model_dump() == {
        "numerator": 3,
        "denominator": 3,
        "not_applicable": 1,
        "value": 1.0,
    }
    assert evaluation.metrics.cited_section_correctness.model_dump() == {
        "numerator": 2,
        "denominator": 2,
        "not_applicable": 2,
        "value": 1.0,
    }
    assert evaluation.metrics.citation_id_validity.model_dump() == {
        "numerator": 2,
        "denominator": 2,
        "not_applicable": 2,
        "value": 1.0,
    }
    assert evaluation.metrics.source_alignment.model_dump() == {
        "numerator": 2,
        "denominator": 2,
        "not_applicable": 2,
        "value": 1.0,
    }
    assert evaluation.metrics.abstention_success.model_dump() == {
        "numerator": 1,
        "denominator": 1,
        "not_applicable": 3,
        "value": 1.0,
    }
    assert evaluation.embedding_algorithm_version == "token-hash-v1"
    assert evaluation.corpus_digest_kind == "indexed-chunks-v1"
    assert len(evaluation.manifest_sha256) == len(evaluation.corpus_sha256) == 64
    assert len(evaluation.git_revision) == 40
    assert len(evaluation.source_fingerprint) == 64


@pytest.mark.parametrize(
    ("field", "wrong_value", "check_name"),
    [
        ("expected_retrieved_section", "Wrong retrieval section", "retrieval_hit_at_k"),
        ("expected_cited_section", "Wrong cited section", "cited_section_correctness"),
        (
            "expected_completed_nodes",
            ["classify_intent", "vector_search", "evaluate_vector_results"],
            "path_match",
        ),
    ],
)
def test_wrong_retrieval_citation_or_path_label_fails_evaluation(
    tmp_path: Path, field: str, wrong_value: object, check_name: str
) -> None:
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    direct[field] = wrong_value

    evaluation = offline_rag.run_rag_evaluation(_write_cases(tmp_path, [direct]), GUIDE)

    assert not evaluation.passed
    assert not evaluation.cases[0].passed
    assert getattr(evaluation.cases[0].checks, check_name) is False


def test_relabeling_a_normal_case_cannot_make_the_adapter_forge_a_citation(
    tmp_path: Path,
) -> None:
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    direct["expected_outcome"] = "invalid_source_citation"
    direct["expected_cited_section"] = None
    direct["expected_failure_stage"] = "grounded_answer_validation"
    direct["expected_completed_nodes"] = [
        "classify_intent",
        "vector_search",
        "evaluate_vector_results",
    ]

    evaluation = offline_rag.run_rag_evaluation(_write_cases(tmp_path, [direct]), GUIDE)
    case = evaluation.cases[0]

    assert case.actual_outcome == "answer"
    assert case.completed_nodes[-1] == "generate_grounded_answer"
    assert case.failure_stage is None
    assert not case.checks.outcome_match
    assert not case.checks.path_match
    assert not evaluation.passed


def test_retrieval_hit_does_not_credit_an_unrelated_cited_section(tmp_path: Path) -> None:
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    direct["question"] = (
        "parameterized SQL queries bind application values exposed credentials "
        "rotate revoke access logs"
    )
    path = _write_cases(tmp_path, [direct])

    evaluation = offline_rag.run_rag_evaluation(path, GUIDE)
    case = evaluation.cases[0]

    assert [item.section for item in case.retrieved] == [
        "Secrets and credential handling",
        "Injection-resistant data access",
    ]
    assert case.cited_evidence[0].section == "Secrets and credential handling"
    assert case.checks.retrieval_hit_at_k is True
    assert case.checks.cited_section_correctness is False
    assert evaluation.metrics.retrieval_hit_at_k.numerator == 1
    assert evaluation.metrics.cited_section_correctness.numerator == 0
    assert not evaluation.passed


def test_unknown_citation_stops_before_completed_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normal_model = offline_rag._OfflineChatModel

    class UnknownCitationModel(normal_model):
        def complete(self, system: str, user: str) -> str:
            answer = super().complete(system, user)
            if "[source:" in answer:
                return "Unknown source [source:never-retrieved]"
            return answer

    monkeypatch.setattr(offline_rag, "_OfflineChatModel", UnknownCitationModel)
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]

    evaluation = offline_rag.run_rag_evaluation(_write_cases(tmp_path, [direct]), GUIDE)
    case = evaluation.cases[0]

    assert case.completed_nodes == ("classify_intent", "vector_search", "evaluate_vector_results")
    assert case.failure_stage == "grounded_answer_validation"
    assert case.error == "invalid_source_citation"
    assert case.cited_ids == ("never-retrieved",)
    assert case.cited_evidence == ()
    assert not evaluation.passed


def test_duplicate_citation_ids_are_deduplicated_and_sources_stay_aligned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normal_model = offline_rag._OfflineChatModel

    class DuplicateCitationModel(normal_model):
        def complete(self, system: str, user: str) -> str:
            answer = super().complete(system, user)
            if "[source:" in answer:
                return f"{answer} Repeated {answer[answer.index('[source:') :]}"
            return answer

    monkeypatch.setattr(offline_rag, "_OfflineChatModel", DuplicateCitationModel)
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]

    evaluation = offline_rag.run_rag_evaluation(_write_cases(tmp_path, [direct]), GUIDE)
    case = evaluation.cases[0]

    assert evaluation.passed
    assert len(case.cited_ids) == len(case.cited_evidence) == 1
    assert case.cited_ids == (case.retrieved[0].id,)
    assert case.checks.citation_id_validity is True
    assert case.checks.source_alignment is True


def test_abstention_stops_at_two_searches_without_retrying_further(tmp_path: Path) -> None:
    abstain = json.loads(CASES.read_text(encoding="utf-8"))["cases"][2]

    evaluation = offline_rag.run_rag_evaluation(_write_cases(tmp_path, [abstain]), GUIDE)
    case = evaluation.cases[0]

    assert evaluation.passed
    assert case.attempts == 2
    assert case.completed_nodes.count("vector_search") == 2
    assert case.completed_nodes.count("rewrite_query") == 1
    assert case.cited_ids == case.cited_evidence == case.retrieved == ()
    assert case.checks.abstention_success is True
    assert evaluation.metrics.retrieval_hit_at_k.denominator == 0
    assert evaluation.metrics.retrieval_hit_at_k.value is None


def test_manifest_digest_uses_the_loaded_case_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = CASES.read_bytes()
    manifest = tmp_path / "cases.json"
    manifest.write_bytes(original)
    revised = json.loads(original)
    revised["cases"][0]["question"] = "Changed after loading"
    real_builder = offline_rag.build_offline_retriever

    def change_manifest_after_load(document_path: Path):
        built = real_builder(document_path)
        manifest.write_text(json.dumps(revised), encoding="utf-8")
        return built

    monkeypatch.setattr(offline_rag, "build_offline_retriever", change_manifest_after_load)

    evaluation = offline_rag.run_rag_evaluation(manifest, GUIDE)

    assert evaluation.passed
    assert evaluation.cases[0].search_queries[0] == (
        "How do parameterized queries bind application values safely?"
    )
    assert evaluation.manifest_sha256 == sha256(original).hexdigest()
    assert evaluation.manifest_sha256 != sha256(manifest.read_bytes()).hexdigest()


def test_corpus_digest_follows_indexed_chunks_after_source_file_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guide = tmp_path / "guide.md"
    original = GUIDE.read_bytes()
    guide.write_bytes(original)
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    manifest = _write_cases(tmp_path, [direct])
    indexed_digest = offline_rag.run_rag_evaluation(manifest, guide).corpus_sha256
    real_builder = offline_rag.build_offline_retriever

    def change_corpus_after_indexing(document_path: Path):
        built = real_builder(document_path)
        guide.write_bytes(original + b"\n\n## Changed after indexing\n")
        return built

    monkeypatch.setattr(offline_rag, "build_offline_retriever", change_corpus_after_indexing)

    evaluation = offline_rag.run_rag_evaluation(manifest, guide)

    assert evaluation.corpus_sha256 == indexed_digest
    assert guide.read_bytes() != original


def test_transient_corpus_edit_and_restore_cannot_change_indexed_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guide = tmp_path / "guide.md"
    original = GUIDE.read_bytes()
    changed = original.replace(
        b"## Injection-resistant data access",
        b"## Injection-safe data access",
    )
    assert changed != original
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    manifest = _write_cases(tmp_path, [direct])

    guide.write_bytes(original)
    original_digest = offline_rag.run_rag_evaluation(manifest, guide).corpus_sha256
    guide.write_bytes(changed)
    indexed_digest = offline_rag.run_rag_evaluation(manifest, guide).corpus_sha256
    assert indexed_digest != original_digest
    guide.write_bytes(original)
    real_builder = offline_rag.build_offline_retriever

    def index_transient_edit(document_path: Path):
        guide.write_bytes(changed)
        built = real_builder(document_path)
        guide.write_bytes(original)
        return built

    monkeypatch.setattr(offline_rag, "build_offline_retriever", index_transient_edit)

    evaluation = offline_rag.run_rag_evaluation(manifest, guide)

    assert guide.read_bytes() == original
    assert evaluation.corpus_sha256 == indexed_digest
    assert evaluation.corpus_sha256 != original_digest


def test_oversized_corpus_is_rejected_before_indexing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversized = tmp_path / "oversized.md"
    oversized.write_bytes(b"x" * (MAX_DOCUMENT_BYTES + 1))
    direct = json.loads(CASES.read_text(encoding="utf-8"))["cases"][0]
    monkeypatch.setattr(
        offline_rag,
        "build_offline_retriever",
        lambda path: pytest.fail("oversized corpus reached Qdrant indexing"),
    )

    with pytest.raises(DocumentIngestionError, match="document_too_large"):
        offline_rag.run_rag_evaluation(_write_cases(tmp_path, [direct]), oversized)
