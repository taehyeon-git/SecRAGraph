"""Measure the multi-engine scanner on pinned labels or an unlabeled local repository.

The evaluator treats target files as inert data. It never runs upstream test scripts.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from security_review.application import scan_path
from security_review.domain.models import ScanReport
from security_review.evaluation.multiengine_benchmark import (
    EvaluationInputError,
    LabeledEvaluation,
    UnlabeledMeasurement,
    evaluate_labeled_corpus,
    load_labeled_corpus,
    measure_unlabeled_repository,
)
from security_review.intelligence.dependency_osv import LiveDependencyAuditor
from security_review.scanner.files import ScanLimits

_ROOT = Path(__file__).resolve().parents[1]


def _scan(target: Path) -> ScanReport:
    return scan_path(target, ScanLimits(), dependency_auditor=LiveDependencyAuditor())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--cases",
        type=Path,
        default=None,
        help="labeled corpus manifest; defaults to the authored regression corpus",
    )
    target.add_argument(
        "--real-repo",
        type=Path,
        help="measure a local repository without claiming accuracy",
    )
    parser.add_argument(
        "--checkout",
        type=Path,
        help="local Git checkout at the manifest's pinned revision for an external corpus",
    )
    parser.add_argument("--output-dir", type=Path, default=_ROOT / "build/evidence")
    parser.add_argument(
        "--staging-dir",
        type=Path,
        help="temporary scanner target parent; use a writable path outside Git ignores",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail if any labeled assessment could not be scored",
    )
    parser.add_argument(
        "--require-match",
        action="store_true",
        help="fail if a scored assessment has a false positive or false negative",
    )
    parser.add_argument(
        "--require-traces",
        action="store_true",
        help="fail if an expected source-to-sink trace is absent or mismatched",
    )
    args = parser.parse_args(argv)
    if args.real_repo is not None and (
        args.checkout is not None
        or args.require_complete
        or args.require_match
        or args.require_traces
    ):
        parser.error("--checkout and labeled gates require --cases")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.staging_dir is not None:
        args.staging_dir.mkdir(parents=True, exist_ok=True)
    result: LabeledEvaluation | UnlabeledMeasurement
    try:
        if args.real_repo is not None:
            result = measure_unlabeled_repository(args.real_repo, _scan)
        else:
            cases = args.cases or _ROOT / "data/evaluation/multiengine_cases.json"
            corpus = load_labeled_corpus(cases, checkout=args.checkout)
            result = evaluate_labeled_corpus(corpus, _scan, staging_root=args.staging_dir)
    except EvaluationInputError as error:
        parser.exit(2, f"evaluation input error: {error}\n")

    (args.output_dir / "multiengine-scanner.json").write_text(
        result.to_json(), encoding="utf-8", newline=""
    )
    (args.output_dir / "multiengine-scanner.md").write_text(
        result.to_markdown(), encoding="utf-8", newline=""
    )
    print(result.to_markdown(), end="")
    if isinstance(result, UnlabeledMeasurement):
        return 0
    if args.require_complete and any(item.status == "unscored" for item in result.assessments):
        return 1
    if args.require_match and (result.metrics.fp or result.metrics.fn):
        return 1
    if args.require_traces and any(
        item.expected_trace is not None and item.trace_status != "verified"
        for item in result.assessments
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
