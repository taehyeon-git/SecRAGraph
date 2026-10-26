"""Pinned, non-executing external scanner challenge adapter."""

from __future__ import annotations

import csv
import re
import shutil
import subprocess  # nosec B404
from collections import Counter
from hashlib import sha256
from io import StringIO
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from security_review.scanner.engine import scan_text_detailed

_EXPECTED = "expectedresults-0.1.csv"
_CHALLENGES = {78: ("PY002",), 89: ("PY005",), 502: ("PY004", "PY006")}
_CASE_ID = re.compile(r"BenchmarkTest[0-9]{5}")
_MAX_EXPECTED_BYTES = 1_000_000
_MAX_SOURCE_BYTES = 250_000
_MAX_SOURCE_TOTAL_BYTES = 20_000_000
_MAX_DISCOVERY_ENTRIES = 10_000


class ExternalCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    cwe_id: str
    expected_rule_ids: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    unsupported_sink_caveat: str
    expected_vulnerable: bool
    detected: bool
    outcome: Literal["tp", "fp", "fn", "tn"]


class ExternalBenchmarkEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    benchmark: Literal["OWASP Benchmark for Python v0.1"] = "OWASP Benchmark for Python v0.1"
    evaluation_kind: Literal["broad_cwe_case_level_challenge"] = "broad_cwe_case_level_challenge"
    broad_cwe_challenge: bool = True
    upstream_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    labeled_total: int = Field(ge=0)
    challenge_labeled: int = Field(ge=0)
    scored_cases: int = Field(ge=0)
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    tn: int = Field(ge=0)
    precision_numerator: int = Field(ge=0)
    precision_denominator: int = Field(ge=0)
    recall_numerator: int = Field(ge=0)
    recall_denominator: int = Field(ge=0)
    unsupported_cwe_counts: dict[str, int]
    missing_case_ids: tuple[str, ...]
    ambiguous_case_ids: tuple[str, ...]
    incomplete_case_ids: tuple[str, ...]
    cases: tuple[ExternalCase, ...]
    has_errors: bool
    coverage_note: str = (
        "Broad case-level challenge only: CWE-78→PY002, CWE-89→PY005, and "
        "CWE-502→PY004/PY006. Shell -c, other SQL APIs, and non-pickle deserializers "
        "remain unsupported; missed cases remain in recall denominators."
    )


def _git(root: Path, arguments: list[str]) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("git_unavailable")
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "-c", "core.fsmonitor=false", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
            shell=False,  # nosec B603
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ValueError("benchmark_git_check_failed") from error
    return result.stdout.strip()


def _labels(raw: bytes) -> tuple[tuple[str, bool, int], ...]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("invalid_expected_results") from error
    rows: list[tuple[str, bool, int]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            parsed = next(csv.reader(StringIO(line), strict=True))
        except (csv.Error, StopIteration) as error:
            raise ValueError("invalid_expected_results") from error
        if len(parsed) != 4:
            raise ValueError("invalid_expected_results")
        case_id, category, truth, cwe = (value.strip() for value in parsed)
        if (
            _CASE_ID.fullmatch(case_id) is None
            or not category
            or len(category) > 100
            or truth not in {"true", "false"}
            or not cwe.isascii()
            or not cwe.isdigit()
            or len(cwe) > 5
        ):
            raise ValueError("invalid_expected_results")
        if case_id in seen:
            raise ValueError("duplicate_expected_case")
        seen.add(case_id)
        rows.append((case_id, truth == "true", int(cwe)))
    if not 1 <= len(rows) <= 5_000:
        raise ValueError("invalid_expected_results")
    return tuple(rows)


def _case_sources(root: Path) -> dict[str, tuple[Path, ...]]:
    testcode = root / "testcode"
    if not testcode.is_dir() or testcode.is_symlink():
        raise ValueError("benchmark_testcode_unavailable")
    sources: dict[str, list[Path]] = {}
    entries = 0
    for candidate in testcode.rglob("*"):
        entries += 1
        if entries > _MAX_DISCOVERY_ENTRIES:
            raise ValueError("benchmark_testcode_too_large")
        if candidate.is_symlink():
            raise ValueError("benchmark_linked_source")
        if candidate.is_file() and candidate.suffix == ".py" and _CASE_ID.fullmatch(candidate.stem):
            sources.setdefault(candidate.stem, []).append(candidate)
    return {case_id: tuple(paths) for case_id, paths in sources.items()}


def run_external_benchmark(
    root: Path, expected_revision: str, expected_sha256: str
) -> ExternalBenchmarkEvaluation:
    """Score broad CWE challenge cases without importing or running target files."""

    if re.fullmatch(r"[0-9a-f]{40}", expected_revision) is None:
        raise ValueError("invalid_benchmark_revision")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("invalid_expected_digest")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("benchmark_root_unavailable")
    resolved_root = root.resolve(strict=True)
    actual_revision = _git(resolved_root, ["rev-parse", "--verify", "HEAD"])
    if actual_revision != expected_revision:
        raise ValueError("benchmark_revision_mismatch")
    status = _git(
        resolved_root,
        ["status", "--porcelain", "--untracked-files=all", "--", _EXPECTED, "testcode"],
    )
    if status:
        raise ValueError("benchmark_checkout_dirty")
    tracked = set(_git(resolved_root, ["ls-files", "--", _EXPECTED, "testcode"]).splitlines())
    if _EXPECTED not in tracked:
        raise ValueError("benchmark_expected_untracked")
    expected_path = resolved_root / _EXPECTED
    if expected_path.is_symlink():
        raise ValueError("benchmark_linked_expected")
    try:
        with expected_path.open("rb") as handle:
            raw_expected = handle.read(_MAX_EXPECTED_BYTES + 1)
    except OSError as error:
        raise ValueError("benchmark_expected_unavailable") from error
    if len(raw_expected) > _MAX_EXPECTED_BYTES:
        raise ValueError("benchmark_expected_too_large")
    if sha256(raw_expected).hexdigest() != expected_sha256:
        raise ValueError("benchmark_expected_digest_mismatch")
    labels = _labels(raw_expected)
    source_map = _case_sources(resolved_root)
    unsupported: Counter[str] = Counter()
    missing: list[str] = []
    ambiguous: list[str] = []
    incomplete: list[str] = []
    cases: list[ExternalCase] = []
    challenge_labeled = 0
    total_source_bytes = 0
    for case_id, vulnerable, cwe in labels:
        rule_ids = _CHALLENGES.get(cwe)
        if rule_ids is None:
            unsupported[f"CWE-{cwe}"] += 1
            continue
        challenge_labeled += 1
        paths = source_map.get(case_id, ())
        if not paths:
            missing.append(case_id)
            continue
        if len(paths) != 1:
            ambiguous.append(case_id)
            continue
        path = paths[0]
        relative = path.relative_to(resolved_root).as_posix()
        if relative not in tracked:
            raise ValueError("benchmark_case_untracked")
        try:
            with path.open("rb") as handle:
                raw_source = handle.read(_MAX_SOURCE_BYTES + 1)
        except OSError as error:
            raise ValueError("benchmark_source_unavailable") from error
        if len(raw_source) > _MAX_SOURCE_BYTES:
            raise ValueError("benchmark_source_too_large")
        total_source_bytes += len(raw_source)
        if total_source_bytes > _MAX_SOURCE_TOTAL_BYTES:
            raise ValueError("benchmark_source_total_too_large")
        try:
            source = raw_source.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("benchmark_source_invalid_utf8") from error
        result = scan_text_detailed(relative, source)
        if result.warnings:
            incomplete.append(case_id)
            continue
        matched_rule_ids = tuple(
            rule_id for rule_id in rule_ids if any(f.rule_id == rule_id for f in result.findings)
        )
        detected = bool(matched_rule_ids)
        outcome: Literal["tp", "fp", "fn", "tn"] = (
            "tp" if vulnerable and detected else "fn" if vulnerable else "fp" if detected else "tn"
        )
        cases.append(
            ExternalCase(
                case_id=case_id,
                cwe_id=f"CWE-{cwe}",
                expected_rule_ids=rule_ids,
                matched_rule_ids=matched_rule_ids,
                unsupported_sink_caveat=(
                    "Only declared rule family is scored; other sink forms may be missed."
                ),
                expected_vulnerable=vulnerable,
                detected=detected,
                outcome=outcome,
            )
        )
    counts = Counter(case.outcome for case in cases)
    tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
    return ExternalBenchmarkEvaluation(
        upstream_revision=expected_revision,
        expected_sha256=expected_sha256,
        labeled_total=len(labels),
        challenge_labeled=challenge_labeled,
        scored_cases=len(cases),
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision_numerator=tp,
        precision_denominator=tp + fp,
        recall_numerator=tp,
        recall_denominator=tp + fn,
        unsupported_cwe_counts=dict(sorted(unsupported.items())),
        missing_case_ids=tuple(missing[:100]),
        ambiguous_case_ids=tuple(ambiguous[:100]),
        incomplete_case_ids=tuple(incomplete[:100]),
        cases=tuple(cases),
        has_errors=bool(missing or ambiguous or incomplete),
    )
