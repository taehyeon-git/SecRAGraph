"""Run fixed, keyless RAG graph cases and publish local evidence files."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from security_review.evaluation.offline_rag import run_rag_evaluation
from security_review.evaluation.rag_render import render_rag_json, render_rag_markdown

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CASES = _ROOT / "data/evaluation/rag_cases.json"
_DEFAULT_DOCUMENT = _ROOT / "data/knowledge/secragraph-security-guidelines.md"


def _atomic_write(path: Path, content: str) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Write JSON/Markdown evidence and fail CI when any fixed label fails."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=_DEFAULT_CASES)
    parser.add_argument("--output-dir", type=Path, default=Path("build/evidence"))
    arguments = parser.parse_args(argv)

    try:
        evaluation = run_rag_evaluation(arguments.cases, _DEFAULT_DOCUMENT)
    except (OSError, ValueError):
        print("Unable to evaluate offline RAG cases.", file=sys.stderr)
        return 2

    json_content = render_rag_json(evaluation)
    markdown_content = render_rag_markdown(evaluation)
    try:
        arguments.output_dir.mkdir(parents=True, exist_ok=True)
        json_path = arguments.output_dir / "rag.json"
        markdown_path = arguments.output_dir / "rag.md"
        _atomic_write(json_path, json_content)
        _atomic_write(markdown_path, markdown_content)
    except (OSError, ValueError):
        print("Unable to write RAG evidence files.", file=sys.stderr)
        return 2

    passed = sum(case.passed for case in evaluation.cases)
    status = "PASS" if evaluation.passed else "FAIL"
    print(f"RAG evidence: {status} ({passed}/{len(evaluation.cases)} cases)")
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 0 if evaluation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
