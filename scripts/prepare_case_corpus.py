"""Prepare bounded case-selected CWE evidence for the local demo pipeline."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from security_review.intelligence.case_corpus import prepare_case_corpus


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cache-root", type=Path, default=None)
    parser.add_argument(
        "--offline", action="store_true", help="Use only a verified cache or demo fallback"
    )
    args = parser.parse_args(argv)
    repo_root: Path = args.repo_root.resolve()
    cache_root: Path = args.cache_root or repo_root / "build/auto-corpus"
    result = prepare_case_corpus(repo_root, cache_root, offline=args.offline)
    print(
        json.dumps(
            {
                "status": result.status,
                "root": str(result.root),
                "manifest_path": str(result.manifest_path),
                "coverage_path": str(result.coverage_path),
                "document_count": result.document_count,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
