"""Opt-in scanner evaluation against a pinned local OWASP Python checkout."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from scripts.run_rag_evidence import _atomic_write
from security_review.evaluation.external_benchmark import run_external_benchmark


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, default=Path("build/evidence/scanner-external.json"))
    arguments = parser.parse_args(argv)
    try:
        result = run_external_benchmark(
            arguments.root, arguments.revision, arguments.expected_sha256
        )
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(arguments.output, result.model_dump_json(indent=2))
    except (OSError, ValueError):
        print(
            "External benchmark inputs are invalid or evidence could not be written.",
            file=sys.stderr,
        )
        return 2
    print(
        f"External broad-CWE challenge: {result.scored_cases}/{result.challenge_labeled} "
        f"cases scored; TP={result.tp} FP={result.fp} FN={result.fn} TN={result.tn}."
    )
    print(f"JSON: {arguments.output}")
    return 1 if result.has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
