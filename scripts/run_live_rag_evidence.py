"""Opt-in provider-backed RAG evidence runner; never part of keyless CI."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import SecretStr

from scripts.run_rag_evidence import _atomic_write
from security_review.config import Settings
from security_review.evaluation.live_rag import run_live_evaluation
from security_review.intelligence.openai_adapters import OpenAIChatAdapter, OpenAIEmbeddingAdapter
from security_review.ports import ChatModel, EmbeddingModel

_ROOT = Path(__file__).resolve().parents[1]


def _build_providers(api_key: str, settings: Settings) -> tuple[ChatModel, EmbeddingModel]:
    """Construct live adapters only after the explicit environment-key gate."""

    secret = SecretStr(api_key)
    return (
        OpenAIChatAdapter.from_openai(api_key=secret, model=settings.openai_chat_model),
        OpenAIEmbeddingAdapter.from_openai(
            api_key=secret,
            model=settings.openai_embedding_model,
            dimension=settings.qdrant_vector_dimension,
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=_ROOT / "data/evaluation/rag_cases.json")
    parser.add_argument(
        "--document",
        type=Path,
        default=_ROOT / "data/knowledge/secragraph-security-guidelines.md",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("build/evidence"))
    arguments = parser.parse_args(argv)

    api_key = os.environ.get("SECRAGRAPH_OPENAI_API_KEY", "")
    if not api_key.strip():
        print("Live RAG evaluation requires SECRAGRAPH_OPENAI_API_KEY.", file=sys.stderr)
        return 2
    try:
        settings = Settings()
        chat_model, embeddings = _build_providers(api_key, settings)
        evaluation = run_live_evaluation(
            arguments.cases,
            arguments.document,
            chat_factory=lambda _case: chat_model,
            embeddings=embeddings,
            chat_model_id=settings.openai_chat_model,
            embedding_model_id=settings.openai_embedding_model,
        )
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        output = arguments.output_dir / "rag-live.json"
        _atomic_write(output, evaluation.model_dump_json(indent=2))
    except Exception:  # Provider SDK failures may contain credentials or prompt content.
        print("Unable to run or write live RAG evidence.", file=sys.stderr)
        return 2
    print(
        f"Live RAG observations: {len(evaluation.cases)} cases, "
        f"{evaluation.provider_errors} provider/graph errors."
    )
    print(f"JSON: {output}")
    return 0 if evaluation.provider_errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
