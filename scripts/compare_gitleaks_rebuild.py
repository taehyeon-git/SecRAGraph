"""Compare release and source-rebuilt Gitleaks on the same inert scanner cases.

Only rule IDs and source locations are compared; raw secret material is never
written to the evidence file or command output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from security_review.evaluation.multiengine_benchmark import (
    EvaluationInputError,
    LabeledCase,
    load_labeled_corpus,
)
from security_review.scanner.external_detectors import GitleaksAdapter


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_case(
    case: LabeledCase, binary: Path
) -> tuple[str, str | None, tuple[tuple[str, str | None, int | None, int | None], ...]]:
    with TemporaryDirectory(prefix="secragraph-gitleaks-parity-") as temporary:
        root = Path(temporary) / "input"
        root.mkdir()
        for relative, source in case.files:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(source, encoding="utf-8")
        result = GitleaksAdapter(binary=str(binary)).scan_snapshot(root, timeout=60)
        identities = tuple(
            sorted(
                [
                    (
                        finding.rule_id,
                        finding.file_path,
                        finding.line_start,
                        finding.line_end,
                    )
                    for finding in result.findings
                ],
                key=lambda item: (item[0], item[1] or "", item[2] or 0, item[3] or 0),
            )
        )
        return result.execution.status, result.execution.version, identities


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--rebuilt", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    for binary in (args.release, args.rebuilt):
        if not binary.is_file():
            parser.error("a Gitleaks binary is missing")
    release_binary = args.release.resolve(strict=True)
    rebuilt_binary = args.rebuilt.resolve(strict=True)
    try:
        corpus = load_labeled_corpus(args.cases)
    except EvaluationInputError as error:
        parser.exit(2, f"invalid comparison cases: {error}\n")
    if corpus.scope != "synthetic_regression":
        parser.error("only the checked-in synthetic corpus is supported")

    finding_count = 0
    for case in corpus.cases:
        release = _scan_case(case, release_binary)
        rebuilt = _scan_case(case, rebuilt_binary)
        if release[0] != "completed" or rebuilt[0] != "completed":
            parser.exit(1, f"gitleaks comparison incomplete: {case.case_id}\n")
        if release[1] != "8.30.1" or rebuilt[1] != "8.30.1":
            parser.exit(1, f"gitleaks version mismatch: {case.case_id}\n")
        if release != rebuilt:
            parser.exit(1, f"gitleaks comparison changed: {case.case_id}\n")
        if case.case_id == "generic-secret" and release[2] != (
            ("GITLEAKS/generic-api-key", "secret.env", 1, 1),
        ):
            parser.exit(1, "gitleaks positive or negative control failed\n")
        finding_count += len(release[2])

    evidence = {
        "schema_version": 1,
        "case_manifest_sha256": corpus.manifest_sha256,
        "case_count": len(corpus.cases),
        "equal_case_count": len(corpus.cases),
        "finding_count_per_binary": finding_count,
        "release_sha256": _sha256(release_binary),
        "rebuilt_sha256": _sha256(rebuilt_binary),
        "scanner_version": "8.30.1",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="",
    )
    print(
        "gitleaks_parity: "
        f"cases={len(corpus.cases)} findings_per_binary={finding_count} all_equal=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
