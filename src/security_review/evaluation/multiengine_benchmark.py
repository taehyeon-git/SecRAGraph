"""Honest labeled accuracy and unlabeled operational scanner measurements.

The evaluator writes inert source fixtures and invokes an injected scan function.
It never imports or executes target source or any upstream benchmark script.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Literal

from security_review.domain.models import Finding, ScanReport, TraceLocation

_CASE_ID = re.compile(r"[a-z][a-z0-9-]{0,100}\Z")
_ENGINE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,179}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40,64}\Z")
_CWE_ID = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_MAX_MANIFEST_BYTES = 2_000_000
_MAX_SOURCE_BYTES = 1_000_000
_MAX_CASE_BYTES = 20_000_000
_MAX_CASES = 10_000
_MAX_ASSESSMENTS = 10_000


class EvaluationInputError(ValueError):
    """Stable, content-free error for malformed or unpinned evaluation input."""


@dataclass(frozen=True, slots=True)
class TraceTruth:
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    required_steps: tuple[tuple[str, int], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "source_file": self.source_file,
            "source_line": self.source_line,
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "required_steps": [{"file": path, "line": line} for path, line in self.required_steps],
        }


@dataclass(frozen=True, slots=True)
class RuleTruth:
    engine: str
    rule_id: str
    file_path: str
    expected_lines: frozenset[int]
    expected_trace: TraceTruth | None = None

    @property
    def key(self) -> str:
        return f"{self.engine}:{self.rule_id}"


@dataclass(frozen=True, slots=True)
class LabeledCase:
    case_id: str
    files: tuple[tuple[str, str], ...]
    assessments: tuple[RuleTruth, ...]
    cwe_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LabeledCorpus:
    scope: Literal["synthetic_regression", "external_challenge"]
    name: str
    manifest_sha256: str
    cases: tuple[LabeledCase, ...]
    source_revision: str | None = None
    ground_truth_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class RuleMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    assessments_scored: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        denominator = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / denominator if denominator else None

    def to_dict(self) -> dict[str, int | float | None]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": self.precision,
            "precision_denominator": self.tp + self.fp,
            "recall": self.recall,
            "recall_denominator": self.tp + self.fn,
            "f1": self.f1,
            "assessments_scored": self.assessments_scored,
        }


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    case_id: str
    engine: str
    rule_id: str
    file_path: str
    status: Literal["scored", "unscored"]
    reason: str | None
    tp: int
    fp: int
    fn: int
    expected_trace: TraceTruth | None = None
    trace_status: Literal["verified", "missing", "mismatched"] | None = None
    observed_trace: tuple[TraceLocation, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "engine": self.engine,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "status": self.status,
            "reason": self.reason,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "expected_trace": (
                self.expected_trace.to_dict() if self.expected_trace is not None else None
            ),
            "trace_status": self.trace_status,
            "observed_trace": [
                {"role": item.role, "file_path": item.file_path, "line_start": item.line_start}
                for item in self.observed_trace
            ],
        }


@dataclass(frozen=True, slots=True)
class LabeledEvaluation:
    corpus: LabeledCorpus
    assessments: tuple[AssessmentResult, ...]
    metrics: RuleMetrics
    by_rule: Mapping[str, RuleMetrics]
    engine_elapsed_ms: Mapping[str, int]
    engine_coverage: Mapping[str, Mapping[str, int]]
    wall_elapsed_ms: int
    cases_scanned: int
    unassessed_finding_count: int

    def to_dict(self) -> dict[str, object]:
        unscored = sum(item.status == "unscored" for item in self.assessments)
        trace_total = sum(item.expected_trace is not None for item in self.assessments)
        trace_scored = sum(
            item.expected_trace is not None and item.status == "scored" for item in self.assessments
        )
        trace_verified = sum(item.trace_status == "verified" for item in self.assessments)
        return {
            "scope": self.corpus.scope,
            "interpretation": (
                "Author-written regression cases; results do not estimate real-world detection."
                if self.corpus.scope == "synthetic_regression"
                else "Pinned external challenge; conclusions apply only to scored labels."
            ),
            "corpus": {
                "name": self.corpus.name,
                "manifest_sha256": self.corpus.manifest_sha256,
                "source_revision": self.corpus.source_revision,
                "ground_truth_sha256": self.corpus.ground_truth_sha256,
            },
            "coverage": {
                "cases_total": len(self.corpus.cases),
                "cases_scanned": self.cases_scanned,
                "assessments_total": len(self.assessments),
                "assessments_scored": len(self.assessments) - unscored,
                "assessments_unscored": unscored,
                "unassessed_finding_count": self.unassessed_finding_count,
                "traces_expected": trace_total,
                "traces_scored": trace_scored,
                "traces_verified": trace_verified,
                "traces_unverified": trace_scored - trace_verified,
                "traces_unscored": trace_total - trace_scored,
            },
            "metrics": self.metrics.to_dict(),
            "by_engine": {
                key: _summarize(
                    tuple(item for item in self.assessments if item.engine == key)
                ).to_dict()
                for key in sorted({item.engine for item in self.assessments})
            },
            "by_rule": {key: value.to_dict() for key, value in sorted(self.by_rule.items())},
            "engine_elapsed_ms": dict(sorted(self.engine_elapsed_ms.items())),
            "engine_coverage": {
                key: dict(values) for key, values in sorted(self.engine_coverage.items())
            },
            "wall_elapsed_ms": self.wall_elapsed_ms,
            "assessments": [item.to_dict() for item in self.assessments],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def to_markdown(self) -> str:
        unscored = sum(item.status == "unscored" for item in self.assessments)
        trace_assessments = [item for item in self.assessments if item.expected_trace is not None]
        trace_scored = sum(item.status == "scored" for item in trace_assessments)
        trace_verified = sum(item.trace_status == "verified" for item in trace_assessments)
        interpretation = (
            "Author-written fixtures measure regression behavior, not real-world detection."
            if self.corpus.scope == "synthetic_regression"
            else "Pinned external challenge; conclusions apply only to scored labels."
        )
        lines = [
            "# Multi-engine scanner evaluation",
            "",
            f"- Scope: {self.corpus.scope}",
            f"- Corpus: {self.corpus.name}",
            f"- Manifest SHA-256: `{self.corpus.manifest_sha256}`",
            f"- Cases scanned: {self.cases_scanned}/{len(self.corpus.cases)}",
            f"- Scored assessments: {len(self.assessments) - unscored}/{len(self.assessments)}",
            f"- Unscored assessments: {unscored}",
            f"- Unassessed findings: {self.unassessed_finding_count}",
            f"- Traces verified: {trace_verified}/{trace_scored} scored expectations",
            f"- Wall time: {self.wall_elapsed_ms} ms",
            "",
            "Incomplete or unavailable engines are unscored, not counted as false negatives.",
            interpretation,
            "Unassessed findings are excluded from the reported precision denominator.",
            "",
            "## Engine coverage and time",
            "",
            "| Engine | Completed / runs | Eligible files | Tool-confirmed files | Time (ms) |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        for engine, record in sorted(self.engine_coverage.items()):
            lines.append(
                f"| `{engine}` | {record['completed']}/{record['runs']} | "
                f"{record['eligible_files']} | {record['scanned_files']} | "
                f"{record['elapsed_ms']} |"
            )
        lines.extend(
            [
                "",
                "## Labeled rule results",
                "",
                "| Engine / rule | TP | FP | FN | Precision | Recall | F1 | Scored |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for key, score in sorted(self.by_rule.items()):
            lines.append(
                f"| `{key}` | {score.tp} | {score.fp} | {score.fn} | "
                f"{_rate(score.precision)} | {_rate(score.recall)} | {_rate(score.f1)} | "
                f"{score.assessments_scored} |"
            )
        if trace_assessments:
            lines.extend(
                [
                    "",
                    "## Source-to-sink trace verification",
                    "",
                    "| Case / rule | Expected source | Required steps | "
                    "Expected sink | Trace status |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for item in trace_assessments:
                expected_trace = item.expected_trace
                if expected_trace is None:
                    continue
                step_text = (
                    ", ".join(f"`{path}:{line}`" for path, line in expected_trace.required_steps)
                    or "—"
                )
                lines.append(
                    f"| `{item.case_id}` / `{item.rule_id}` | "
                    f"`{expected_trace.source_file}:{expected_trace.source_line}` | "
                    f"{step_text} | "
                    f"`{expected_trace.sink_file}:{expected_trace.sink_line}` | "
                    f"{item.trace_status or 'unscored'} |"
                )
        unscored_items = [item for item in self.assessments if item.status == "unscored"]
        if unscored_items:
            lines.extend(["", "## Unscored assessments", ""])
            lines.extend(
                f"- `{item.case_id}` / `{item.engine}:{item.rule_id}`: {item.reason}"
                for item in unscored_items
            )
        return "\n".join(lines).rstrip() + "\n"


@dataclass(frozen=True, slots=True)
class UnlabeledMeasurement:
    repository_name: str
    source_revision: str | None
    finding_count: int
    engines: Mapping[str, dict[str, object]]
    wall_elapsed_ms: int

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": "unlabeled_repository",
            "interpretation": (
                "Operational coverage and timing only; no vulnerability truth labels were supplied."
            ),
            "repository_name": self.repository_name,
            "source_revision": self.source_revision,
            "finding_count": self.finding_count,
            "engines": dict(sorted(self.engines.items())),
            "wall_elapsed_ms": self.wall_elapsed_ms,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def to_markdown(self) -> str:
        lines = [
            "# Unlabeled repository scan measurement",
            "",
            f"- Repository: {self.repository_name}",
            f"- Revision: `{self.source_revision or 'unavailable'}`",
            f"- Findings: {self.finding_count}",
            f"- Wall time: {self.wall_elapsed_ms} ms",
            "",
            "This repository has no independently reviewed truth labels, so no TP, FP, FN, "
            "precision, or recall is reported.",
            "",
            "| Engine | Status | Submitted files | Proven scanned files | Time (ms) | Hits |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
        for engine, data in sorted(self.engines.items()):
            lines.append(
                f"| `{engine}` | {data['status']} | {data['eligible_files']} | "
                f"{data['scanned_files']} | {data['elapsed_ms']} | {data['finding_count']} |"
            )
        return "\n".join(lines) + "\n"


def _rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def _relative_path(raw: object) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or any(ord(ch) < 32 for ch in raw):
        raise EvaluationInputError("invalid_file_path")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or ".." in path.parts
        or "." in path.parts
        or ":" in path.parts[0]
        or len(raw) > 512
    ):
        raise EvaluationInputError("invalid_file_path")
    return raw


def _safe_text(raw: object, code: str, maximum: int = _MAX_SOURCE_BYTES) -> str:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise EvaluationInputError(code)
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EvaluationInputError(code) from error
    if len(encoded) > maximum:
        raise EvaluationInputError(code)
    return raw


def _read_bounded(path: Path, maximum: int, code: str) -> bytes:
    try:
        with path.open("rb") as source:
            body = source.read(maximum + 1)
    except OSError as error:
        raise EvaluationInputError(code) from error
    if len(body) > maximum:
        raise EvaluationInputError(code)
    return body


def _head_revision(checkout: Path) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        output = subprocess.run(  # noqa: S603  # nosec B603
            [git, "-C", str(checkout), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    revision = output.stdout.strip().lower()
    return revision if output.returncode == 0 and _GIT_SHA.fullmatch(revision) else None


def _validate_provenance(
    raw: object, checkout: Path | None
) -> tuple[Literal["synthetic_regression", "external_challenge"], str, str | None, str | None]:
    if not isinstance(raw, dict):
        raise EvaluationInputError("invalid_provenance")
    kind = raw.get("kind")
    name = _safe_text(raw.get("name"), "invalid_provenance", 120)
    if any(ord(character) < 32 for character in name):
        raise EvaluationInputError("invalid_provenance")
    if kind == "synthetic":
        if set(raw) != {"kind", "name"}:
            raise EvaluationInputError("invalid_provenance")
        return "synthetic_regression", name, None, None
    if kind != "external" or set(raw) != {
        "kind",
        "name",
        "source_revision",
        "ground_truth_path",
        "ground_truth_sha256",
        "license",
    }:
        raise EvaluationInputError("invalid_provenance")
    if checkout is None or not checkout.is_dir() or checkout.is_symlink():
        raise EvaluationInputError("external_checkout_required")
    revision = raw["source_revision"]
    if not isinstance(revision, str) or not _GIT_SHA.fullmatch(revision):
        raise EvaluationInputError("invalid_source_revision")
    if _head_revision(checkout) != revision:
        raise EvaluationInputError("source_revision_mismatch")
    label_path = _relative_path(raw["ground_truth_path"])
    expected_hash = raw["ground_truth_sha256"]
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise EvaluationInputError("invalid_ground_truth_hash")
    _safe_text(raw["license"], "invalid_provenance", 120)
    label_file = checkout.joinpath(*PurePosixPath(label_path).parts)
    if label_file.is_symlink() or not label_file.resolve(strict=False).is_relative_to(
        checkout.resolve(strict=True)
    ):
        raise EvaluationInputError("ground_truth_outside_checkout")
    actual_hash = sha256(
        _read_bounded(label_file, 5_000_000, "ground_truth_unreadable")
    ).hexdigest()
    if actual_hash != expected_hash:
        raise EvaluationInputError("ground_truth_hash_mismatch")
    return "external_challenge", name, revision, expected_hash


def _source_file(raw: object, *, checkout: Path | None, scope: str) -> tuple[str, str]:
    if not isinstance(raw, dict) or "path" not in raw:
        raise EvaluationInputError("invalid_case_file")
    path = _relative_path(raw["path"])
    if scope == "synthetic_regression":
        if set(raw) != {"path", "source"}:
            raise EvaluationInputError("invalid_case_file")
        return path, _safe_text(raw["source"], "invalid_case_source")
    if set(raw) != {"path", "sha256"} or checkout is None:
        raise EvaluationInputError("invalid_case_file")
    expected_hash = raw["sha256"]
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise EvaluationInputError("invalid_case_hash")
    candidate = checkout.joinpath(*PurePosixPath(path).parts)
    if candidate.is_symlink() or not candidate.resolve(strict=False).is_relative_to(
        checkout.resolve(strict=True)
    ):
        raise EvaluationInputError("invalid_case_file")
    body = _read_bounded(candidate, _MAX_SOURCE_BYTES, "case_file_unreadable")
    if sha256(body).hexdigest() != expected_hash:
        raise EvaluationInputError("case_file_hash_mismatch")
    try:
        source = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvaluationInputError("invalid_case_source") from error
    return path, _safe_text(source, "invalid_case_source")


def _truth(raw: object, sources: Mapping[str, str]) -> RuleTruth:
    required = {
        "engine",
        "rule_id",
        "file_path",
        "expected_lines",
    }
    if (
        not isinstance(raw, dict)
        or not required <= set(raw)
        or not set(raw) <= required | {"expected_trace"}
    ):
        raise EvaluationInputError("invalid_assessment")
    engine, rule_id = raw["engine"], raw["rule_id"]
    if (
        not isinstance(engine, str)
        or not _ENGINE_ID.fullmatch(engine)
        or not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
    ):
        raise EvaluationInputError("invalid_assessment")
    path = _relative_path(raw["file_path"])
    if path not in sources:
        raise EvaluationInputError("assessment_file_missing")
    lines = raw["expected_lines"]
    if not isinstance(lines, list) or len(lines) > 1_000 or len(lines) != len(set(map(str, lines))):
        raise EvaluationInputError("invalid_expected_lines")
    line_count = len(sources[path].splitlines())
    if any(
        isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= line_count
        for line in lines
    ):
        raise EvaluationInputError("label_line_out_of_range")
    trace = None
    if "expected_trace" in raw:
        trace_raw = raw["expected_trace"]
        trace_keys = {"source_file", "source_line", "sink_file", "sink_line"}
        if (
            not isinstance(trace_raw, dict)
            or not trace_keys <= set(trace_raw)
            or not set(trace_raw) <= trace_keys | {"required_steps"}
        ):
            raise EvaluationInputError("invalid_expected_trace")
        source_file = _relative_path(trace_raw["source_file"])
        sink_file = _relative_path(trace_raw["sink_file"])
        source_line = trace_raw["source_line"]
        sink_line = trace_raw["sink_line"]
        if (
            source_file not in sources
            or sink_file != path
            or len(lines) != 1
            or isinstance(source_line, bool)
            or not isinstance(source_line, int)
            or not 1 <= source_line <= len(sources[source_file].splitlines())
            or isinstance(sink_line, bool)
            or not isinstance(sink_line, int)
            or sink_line != lines[0]
        ):
            raise EvaluationInputError("invalid_expected_trace")
        raw_steps = trace_raw.get("required_steps", [])
        if not isinstance(raw_steps, list) or len(raw_steps) > 32:
            raise EvaluationInputError("invalid_expected_trace")
        required_steps: list[tuple[str, int]] = []
        for raw_step in raw_steps:
            if not isinstance(raw_step, dict) or set(raw_step) != {"file", "line"}:
                raise EvaluationInputError("invalid_expected_trace")
            step_file = _relative_path(raw_step["file"])
            step_line = raw_step["line"]
            if (
                step_file not in sources
                or isinstance(step_line, bool)
                or not isinstance(step_line, int)
                or not 1 <= step_line <= len(sources[step_file].splitlines())
            ):
                raise EvaluationInputError("invalid_expected_trace")
            required_steps.append((step_file, step_line))
        if len(required_steps) != len(set(required_steps)):
            raise EvaluationInputError("invalid_expected_trace")
        trace = TraceTruth(source_file, source_line, sink_file, sink_line, tuple(required_steps))
    return RuleTruth(engine, rule_id, path, frozenset(lines), trace)


def load_labeled_corpus(path: Path, *, checkout: Path | None = None) -> LabeledCorpus:
    """Load bounded synthetic labels or verify an immutable local external checkout."""

    body = _read_bounded(path, _MAX_MANIFEST_BYTES, "manifest_unreadable")
    try:
        manifest = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationInputError("manifest_invalid_json") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "provenance", "cases"}
        or manifest["schema_version"] != 1
    ):
        raise EvaluationInputError("manifest_invalid_schema")
    scope, name, revision, truth_hash = _validate_provenance(manifest["provenance"], checkout)
    raw_cases = manifest["cases"]
    if not isinstance(raw_cases, list) or not raw_cases or len(raw_cases) > _MAX_CASES:
        raise EvaluationInputError("invalid_case_count")
    cases: list[LabeledCase] = []
    ids: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict) or set(raw_case) != {
            "case_id",
            "files",
            "assessments",
            "cwe_ids",
        }:
            raise EvaluationInputError("invalid_case")
        case_id = raw_case["case_id"]
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or case_id in ids:
            raise EvaluationInputError("invalid_case_id")
        ids.add(case_id)
        raw_cwe_ids = raw_case["cwe_ids"]
        if (
            not isinstance(raw_cwe_ids, list)
            or len(raw_cwe_ids) > 100
            or any(not isinstance(item, str) or not _CWE_ID.fullmatch(item) for item in raw_cwe_ids)
            or len(raw_cwe_ids) != len(set(raw_cwe_ids))
        ):
            raise EvaluationInputError("invalid_case_cwe_ids")
        raw_files = raw_case["files"]
        if not isinstance(raw_files, list) or not raw_files or len(raw_files) > 500:
            raise EvaluationInputError("invalid_case_file_count")
        files = tuple(_source_file(item, checkout=checkout, scope=scope) for item in raw_files)
        if len({path for path, _ in files}) != len(files):
            raise EvaluationInputError("duplicate_case_file")
        if sum(len(source.encode("utf-8")) for _, source in files) > _MAX_CASE_BYTES:
            raise EvaluationInputError("case_too_large")
        sources = dict(files)
        raw_assessments = raw_case["assessments"]
        if (
            not isinstance(raw_assessments, list)
            or not raw_assessments
            or len(raw_assessments) > _MAX_ASSESSMENTS
        ):
            raise EvaluationInputError("invalid_assessment_count")
        assessments = tuple(_truth(item, sources) for item in raw_assessments)
        identities = [(item.engine, item.rule_id, item.file_path) for item in assessments]
        if len(identities) != len(set(identities)):
            raise EvaluationInputError("duplicate_assessment")
        cases.append(LabeledCase(case_id, files, assessments, tuple(raw_cwe_ids)))
    return LabeledCorpus(scope, name, sha256(body).hexdigest(), tuple(cases), revision, truth_hash)


def _matching_trace(
    findings: tuple[Finding, ...], expected: TraceTruth
) -> tuple[Literal["verified", "missing", "mismatched"], tuple[TraceLocation, ...]]:
    observed: tuple[TraceLocation, ...] = ()
    for finding in findings:
        if finding.line_start != expected.sink_line or not finding.trace:
            continue
        observed = finding.trace
        source = next((item for item in observed if item.role == "source"), None)
        sink = next((item for item in reversed(observed) if item.role == "sink"), None)
        if (
            source is not None
            and sink is not None
            and observed[0].role == "source"
            and observed[-1].role == "sink"
            and source.file_path == expected.source_file
            and source.line_start == expected.source_line
            and sink.file_path == expected.sink_file
            and sink.line_start == expected.sink_line
            and all(
                any(
                    item.role == "step"
                    and item.file_path == step_file
                    and item.line_start == step_line
                    for item in observed
                )
                for step_file, step_line in expected.required_steps
            )
        ):
            return "verified", observed
    return ("mismatched" if observed else "missing"), observed


def _score_truth(case_id: str, truth: RuleTruth, report: ScanReport | None) -> AssessmentResult:
    if report is None:
        return AssessmentResult(
            case_id,
            truth.engine,
            truth.rule_id,
            truth.file_path,
            "unscored",
            "scan_failed",
            0,
            0,
            0,
            expected_trace=truth.expected_trace,
        )
    executions = [item for item in report.executions if item.engine == truth.engine]
    if len(executions) != 1:
        return AssessmentResult(
            case_id,
            truth.engine,
            truth.rule_id,
            truth.file_path,
            "unscored",
            "engine_execution_missing",
            0,
            0,
            0,
            expected_trace=truth.expected_trace,
        )
    execution = executions[0]
    if execution.status != "completed" or truth.file_path not in execution.eligible_files:
        reason = execution.reason or (
            "file_not_eligible" if execution.status == "completed" else f"engine_{execution.status}"
        )
        return AssessmentResult(
            case_id,
            truth.engine,
            truth.rule_id,
            truth.file_path,
            "unscored",
            reason,
            0,
            0,
            0,
            expected_trace=truth.expected_trace,
        )
    matching_findings = tuple(
        finding
        for finding in report.findings
        if finding.engine == truth.engine
        and finding.rule_id == truth.rule_id
        and finding.file_path == truth.file_path
    )
    actual = {finding.line_start for finding in matching_findings}
    expected = truth.expected_lines
    trace_status = None
    observed_trace: tuple[TraceLocation, ...] = ()
    if truth.expected_trace is not None:
        trace_status, observed_trace = _matching_trace(matching_findings, truth.expected_trace)
    return AssessmentResult(
        case_id,
        truth.engine,
        truth.rule_id,
        truth.file_path,
        "scored",
        None,
        len(actual & expected),
        len(actual - expected),
        len(expected - actual),
        expected_trace=truth.expected_trace,
        trace_status=trace_status,
        observed_trace=observed_trace,
    )


def _summarize(assessments: tuple[AssessmentResult, ...]) -> RuleMetrics:
    scored = tuple(item for item in assessments if item.status == "scored")
    return RuleMetrics(
        tp=sum(item.tp for item in scored),
        fp=sum(item.fp for item in scored),
        fn=sum(item.fn for item in scored),
        assessments_scored=len(scored),
    )


def evaluate_labeled_corpus(
    corpus: LabeledCorpus,
    scanner: Callable[[Path], ScanReport],
    *,
    staging_root: Path | None = None,
) -> LabeledEvaluation:
    """Score only explicitly assessed engine/rule/file tuples on completed runs."""

    started = monotonic()
    assessments: list[AssessmentResult] = []
    engine_elapsed: defaultdict[str, int] = defaultdict(int)
    engine_coverage: dict[str, dict[str, int]] = {}
    cases_scanned = 0
    unassessed_count = 0
    for case in corpus.cases:
        with TemporaryDirectory(prefix="secragraph-eval-", dir=staging_root) as temporary:
            root = Path(temporary)
            for path, source in case.files:
                target = root.joinpath(*PurePosixPath(path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8", newline="")
            try:
                report = scanner(root)
            except Exception:
                report = None
        if isinstance(report, ScanReport):
            cases_scanned += 1
            for execution in report.executions:
                engine_elapsed[execution.engine] += execution.elapsed_ms
                coverage = engine_coverage.setdefault(
                    execution.engine,
                    {
                        "runs": 0,
                        "completed": 0,
                        "partial": 0,
                        "not_run": 0,
                        "error": 0,
                        "skipped": 0,
                        "eligible_files": 0,
                        "scanned_files": 0,
                        "elapsed_ms": 0,
                    },
                )
                coverage["runs"] += 1
                coverage[execution.status] += 1
                coverage["eligible_files"] += len(execution.eligible_files)
                coverage["scanned_files"] += len(execution.scanned_files)
                coverage["elapsed_ms"] += execution.elapsed_ms
            assessed = {
                (truth.engine, truth.rule_id, truth.file_path) for truth in case.assessments
            }
            unassessed_count += sum(
                (finding.engine, finding.rule_id, finding.file_path) not in assessed
                for finding in report.findings
            )
        else:
            report = None
        assessments.extend(_score_truth(case.case_id, truth, report) for truth in case.assessments)
    ordered = tuple(assessments)
    by_rule: dict[str, RuleMetrics] = {}
    for key in sorted({f"{item.engine}:{item.rule_id}" for item in ordered}):
        by_rule[key] = _summarize(
            tuple(item for item in ordered if f"{item.engine}:{item.rule_id}" == key)
        )
    return LabeledEvaluation(
        corpus=corpus,
        assessments=ordered,
        metrics=_summarize(ordered),
        by_rule=by_rule,
        engine_elapsed_ms=engine_elapsed,
        engine_coverage=engine_coverage,
        wall_elapsed_ms=max(0, round((monotonic() - started) * 1000)),
        cases_scanned=cases_scanned,
        unassessed_finding_count=unassessed_count,
    )


def measure_unlabeled_repository(
    repository: Path, scanner: Callable[[Path], ScanReport]
) -> UnlabeledMeasurement:
    """Report operation counts on an unlabeled tree without accuracy language."""

    if not repository.is_dir() or repository.is_symlink():
        raise EvaluationInputError("repository_unavailable")
    started = monotonic()
    report = scanner(repository)
    engines: dict[str, dict[str, object]] = {}
    for execution in report.executions:
        engines[execution.engine] = {
            "status": execution.status,
            "version": execution.version,
            "eligible_files": len(execution.eligible_files),
            "scanned_files": len(execution.scanned_files),
            "elapsed_ms": execution.elapsed_ms,
            "finding_count": sum(item.engine == execution.engine for item in report.findings),
            "reason": execution.reason,
        }
    return UnlabeledMeasurement(
        repository_name=repository.name,
        source_revision=_head_revision(repository),
        finding_count=len(report.findings),
        engines=engines,
        wall_elapsed_ms=max(0, round((monotonic() - started) * 1000)),
    )
