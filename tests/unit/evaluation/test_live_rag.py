"""Live-provider evidence is opt-in and does not claim factual correctness."""

from __future__ import annotations

from pathlib import Path

import pytest

from security_review.evaluation.live_rag import run_live_evaluation
from security_review.evaluation.offline_rag import TokenHashEmbeddingModel, _OfflineChatModel


def test_injected_keyless_models_exercise_real_graph_and_local_qdrant() -> None:
    result = run_live_evaluation(
        Path("data/evaluation/rag_cases.json"),
        Path("data/knowledge/secragraph-security-guidelines.md"),
        chat_factory=_OfflineChatModel,
        embeddings=TokenHashEmbeddingModel(),
        chat_model_id="fake-chat",
        embedding_model_id="token-hash-test",
    )

    assert len(result.cases) == 3
    assert result.provider_errors == 0
    assert result.metrics["route"].denominator == 3
    assert all(case.factual_support == "requires_human_review" for case in result.cases)
    assert all(case.answer_sha256 is None or len(case.answer_sha256) == 64 for case in result.cases)
    assert len(result.corpus_sha256) == 64
    assert result.chat_model_id == "fake-chat"


def test_provider_failure_is_counted_without_quality_claim() -> None:
    def failing_factory(_case: object) -> object:
        raise RuntimeError("private provider diagnostic")

    result = run_live_evaluation(
        Path("data/evaluation/rag_cases.json"),
        Path("data/knowledge/secragraph-security-guidelines.md"),
        chat_factory=failing_factory,
        embeddings=TokenHashEmbeddingModel(),
        chat_model_id="fake-chat",
        embedding_model_id="token-hash-test",
    )

    assert result.provider_errors == 3
    assert result.metrics["route"].denominator == 0
    assert all(case.error == "provider_or_graph_error" for case in result.cases)
    assert "private provider diagnostic" not in result.model_dump_json()


def test_cli_without_key_stops_before_provider_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import run_live_rag_evidence

    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "")

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("provider must not be constructed")

    monkeypatch.setattr(run_live_rag_evidence, "_build_providers", forbidden)
    assert run_live_rag_evidence.main([]) == 2


def test_cli_sanitizes_unexpected_provider_setup_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import run_live_rag_evidence

    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "fake-test-key")

    def failing_provider(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("private provider diagnostic")

    monkeypatch.setattr(run_live_rag_evidence, "_build_providers", failing_provider)
    assert run_live_rag_evidence.main([]) == 2
    captured = capsys.readouterr()
    assert "private provider diagnostic" not in captured.err
    assert "fake-test-key" not in captured.err
