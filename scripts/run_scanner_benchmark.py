"""Run the safe synthetic scanner corpus through the public scan facade."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from security_review.evaluation.scanner_benchmark import run_scanner_benchmark

_ROOT = Path(__file__).resolve().parents[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=_ROOT / "data/evaluation/scanner_cases.json")
    parser.add_argument("--output-dir", type=Path, default=_ROOT / "build/evidence")
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="report finding mismatches while still enforcing complete scan coverage",
    )
    args = parser.parse_args(argv)

    result = run_scanner_benchmark(args.cases)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "scanner.json").write_text(result.to_json(), encoding="utf-8", newline="")
    (args.output_dir / "scanner.md").write_text(result.to_markdown(), encoding="utf-8", newline="")
    print(result.to_markdown(), end="")
    return int(
        result.has_coverage_failures or (result.has_finding_mismatches and not args.baseline)
    )


if __name__ == "__main__":
    raise SystemExit(main())
