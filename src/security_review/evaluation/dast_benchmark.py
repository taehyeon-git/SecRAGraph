"""Score labelled disposable API DAST cases from completed normalized reports."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from security_review.domain.models import ScanExecution, ScanReport

_ID = re.compile(r"[a-z][a-z0-9-]{0,99}\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,199})\Z")
_RULE = re.compile(r"ZAP/[1-9][0-9]{1,5}\Z")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PINNED_ZAP = re.compile(r"ghcr\.io/zaproxy/zaproxy:[a-z0-9.-]+@sha256:[0-9a-f]{64}\Z")
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_CASES = 1_000


class DastBenchmarkInputError(ValueError):
    """Stable, content-free failure for an incomplete or malformed benchmark."""


@dataclass(frozen=True, slots=True)
class DastBenchmarkCase:
    id: str
    mode: Literal["passive", "active"]
    method: Literal["GET"]
    path: str
    rule_id: str
    cwe_id: str
    expected: bool
    proof: Literal["route_request", "attack_probe"]


@dataclass(frozen=True, slots=True)
class DastBenchmarkManifest:
    name: str
    provenance: Literal["author-written-synthetic"]
    sha256: str
    cases: tuple[DastBenchmarkCase, ...]


@dataclass(frozen=True, slots=True)
class DastMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

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
            "tn": self.tn,
            "precision": self.precision,
            "precision_denominator": self.tp + self.fp,
            "recall": self.recall,
            "recall_denominator": self.tp + self.fn,
            "f1": self.f1,
            "cases_scored": self.tp + self.fp + self.fn + self.tn,
        }


@dataclass(frozen=True, slots=True)
class DastCaseResult:
    id: str
    mode: str
    method: str
    path: str
    rule_id: str
    cwe_id: str
    expected: bool
    detected: bool
    cwe_match: bool | None
    outcome: Literal["TP", "FP", "FN", "TN"]
    proof_delta: int

    def to_dict(self) -> dict[str, str | bool | int | None]:
        return {
            "id": self.id,
            "mode": self.mode,
            "method": self.method,
            "path": self.path,
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "expected": self.expected,
            "detected": self.detected,
            "cwe_match": self.cwe_match,
            "outcome": self.outcome,
            "proof_delta": self.proof_delta,
        }


@dataclass(frozen=True, slots=True)
class DastBenchmarkResult:
    manifest_name: str
    manifest_sha256: str
    provenance: str
    fixture_image_id: str
    source_revision: str
    source_dirty: bool
    zap_version: str
    passive_elapsed_ms: int
    active_elapsed_ms: int
    total_elapsed_ms: int
    cases: tuple[DastCaseResult, ...]
    rules: tuple[tuple[str, DastMetrics], ...]
    metrics: DastMetrics
    unassessed_findings: int
    cwe_mismatch_cases: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "scope": "author_written_regression",
            "manifest_name": self.manifest_name,
            "manifest_sha256": self.manifest_sha256,
            "provenance": self.provenance,
            "fixture_image_id": self.fixture_image_id,
            "source_revision": self.source_revision,
            "source_dirty": self.source_dirty,
            "zap_version": self.zap_version,
            "execution_status": {"passive": "completed", "active": "completed"},
            "coverage": {"cases_scored": len(self.cases), "cases_total": len(self.cases)},
            "timing": {
                "passive_elapsed_ms": self.passive_elapsed_ms,
                "active_elapsed_ms": self.active_elapsed_ms,
                "total_elapsed_ms": self.total_elapsed_ms,
            },
            "metrics": self.metrics.to_dict(),
            "rules": {rule: metrics.to_dict() for rule, metrics in self.rules},
            "cases": [case.to_dict() for case in self.cases],
            "unassessed_findings": self.unassessed_findings,
            "cwe_mismatch_cases": self.cwe_mismatch_cases,
            "unassessed_scope": "normalized_findings_only",
        }


def _strict_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DastBenchmarkInputError("duplicate_json_key")
        result[key] = value
    return result


def _record(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DastBenchmarkInputError("invalid_manifest_record")
    return value


def load_manifest(path: Path) -> DastBenchmarkManifest:
    """Load a bounded, exactly labelled fixture manifest and pin its raw SHA-256."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DastBenchmarkInputError("manifest_unavailable") from error
    if len(raw) > _MAX_MANIFEST_BYTES or not raw:
        raise DastBenchmarkInputError("invalid_manifest_size")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_pairs)
    except (UnicodeError, ValueError) as error:
        raise DastBenchmarkInputError("invalid_manifest_json") from error
    root = _record(payload, {"schema_version", "name", "provenance", "cases"})
    if root["schema_version"] != 1 or type(root["schema_version"]) is not int:
        raise DastBenchmarkInputError("invalid_manifest_schema")
    name = root["name"]
    if not isinstance(name, str) or not _ID.fullmatch(name):
        raise DastBenchmarkInputError("invalid_manifest_name")
    if root["provenance"] != "author-written-synthetic":
        raise DastBenchmarkInputError("invalid_manifest_provenance")
    rows = root["cases"]
    if not isinstance(rows, list) or not 2 <= len(rows) <= _MAX_CASES:
        raise DastBenchmarkInputError("invalid_manifest_cases")
    cases: list[DastBenchmarkCase] = []
    seen_ids: set[str] = set()
    seen_labels: set[tuple[str, str, str, str]] = set()
    rule_labels: dict[str, set[bool]] = defaultdict(set)
    rule_cwes: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        item = _record(
            row,
            {"id", "mode", "method", "path", "rule_id", "cwe_id", "expected", "proof"},
        )
        case_id, mode, method, route = (item[key] for key in ("id", "mode", "method", "path"))
        rule_id, cwe_id, expected, proof = (
            item[key] for key in ("rule_id", "cwe_id", "expected", "proof")
        )
        if not isinstance(case_id, str) or not _ID.fullmatch(case_id):
            raise DastBenchmarkInputError("invalid_case_id")
        if mode not in ("active", "passive") or method != "GET":
            raise DastBenchmarkInputError("invalid_case_mode")
        if not isinstance(route, str) or not _PATH.fullmatch(route) or "//" in route:
            raise DastBenchmarkInputError("invalid_case_path")
        if not isinstance(rule_id, str) or not _RULE.fullmatch(rule_id):
            raise DastBenchmarkInputError("invalid_case_rule")
        if not isinstance(cwe_id, str) or not _CWE.fullmatch(cwe_id):
            raise DastBenchmarkInputError("invalid_case_cwe")
        if type(expected) is not bool or proof != (
            "attack_probe" if mode == "active" else "route_request"
        ):
            raise DastBenchmarkInputError("invalid_case_proof")
        label = (mode, rule_id, method, route)
        if case_id in seen_ids or label in seen_labels:
            raise DastBenchmarkInputError("duplicate_case_label")
        seen_ids.add(case_id)
        seen_labels.add(label)
        rule_labels[rule_id].add(expected)
        rule_cwes[rule_id].add(cwe_id)
        cases.append(
            DastBenchmarkCase(case_id, mode, method, route, rule_id, cwe_id, expected, proof)
        )
    if any(labels != {False, True} for labels in rule_labels.values()):
        raise DastBenchmarkInputError("unbalanced_case_labels")
    if any(len(cwes) != 1 for cwes in rule_cwes.values()):
        raise DastBenchmarkInputError("inconsistent_case_cwe")
    return DastBenchmarkManifest(
        name, "author-written-synthetic", sha256(raw).hexdigest(), tuple(cases)
    )


def _execution(report: ScanReport, mode: str) -> ScanExecution:
    executions = [
        item
        for item in report.executions
        if item.engine == "zap" and item.kind == "dast" and f"openapi-{mode}" in item.checks
    ]
    if len(executions) != 1 or executions[0].status != "completed":
        raise DastBenchmarkInputError("incomplete_execution")
    return executions[0]


def _counter(snapshot: Mapping[str, object], name: str, path: str) -> int:
    counters = snapshot.get(name)
    if not isinstance(counters, dict):
        raise DastBenchmarkInputError("missing_proof_counter")
    value = counters.get(path)
    if type(value) is not int or value < 0:
        raise DastBenchmarkInputError("missing_proof_counter")
    return value


def _metrics(cases: tuple[DastCaseResult, ...]) -> DastMetrics:
    counts = {
        name: sum(case.outcome == name for case in cases) for name in ("TP", "FP", "FN", "TN")
    }
    return DastMetrics(counts["TP"], counts["FP"], counts["FN"], counts["TN"])


def evaluate_dast_benchmark(
    manifest: DastBenchmarkManifest,
    passive_report: ScanReport,
    active_report: ScanReport,
    before_passive: Mapping[str, object],
    after_passive: Mapping[str, object],
    after_active: Mapping[str, object],
    *,
    fixture_image_id: str,
    source_revision: str,
    total_elapsed_ms: int,
    source_dirty: bool = False,
) -> DastBenchmarkResult:
    """Score exact rule/method/path pairs after checking execution and visit proofs."""

    if not _IMAGE.fullmatch(fixture_image_id) or not _SHA.fullmatch(source_revision):
        raise DastBenchmarkInputError("invalid_benchmark_identity")
    if type(source_dirty) is not bool or type(total_elapsed_ms) is not int or total_elapsed_ms < 0:
        raise DastBenchmarkInputError("invalid_benchmark_timing")
    passive = _execution(passive_report, "passive")
    active = _execution(active_report, "active")
    if (
        not passive.version
        or not _PINNED_ZAP.fullmatch(passive.version)
        or passive.version != active.version
    ):
        raise DastBenchmarkInputError("inconsistent_zap_version")
    active_seeds = {
        f"{case.method} {case.path}" for case in manifest.cases if case.mode == "active"
    }
    if set(active.eligible_endpoints) != active_seeds or len(active.eligible_endpoints) != len(
        active_seeds
    ):
        raise DastBenchmarkInputError("active_seed_mismatch")
    passive_seeds = {
        f"{case.method} {case.path}" for case in manifest.cases if case.mode == "passive"
    }
    if not passive_seeds.issubset(set(passive.eligible_endpoints)):
        raise DastBenchmarkInputError("passive_seed_mismatch")
    proof_deltas: dict[str, int] = {}
    for case in manifest.cases:
        name = "attack_probes" if case.mode == "active" else "route_requests"
        earlier, later = (
            (after_passive, after_active)
            if case.mode == "active"
            else (before_passive, after_passive)
        )
        delta = _counter(later, name, case.path) - _counter(earlier, name, case.path)
        if delta <= 0:
            raise DastBenchmarkInputError("case_proof_missing")
        proof_deltas[case.id] = delta
    assessed = {(case.mode, case.rule_id, case.method, case.path) for case in manifest.cases}
    detected: set[tuple[str, str, str, str]] = set()
    observed_cwes: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    unassessed = 0
    for mode, report in (("passive", passive_report), ("active", active_report)):
        for finding in report.findings:
            key = (mode, finding.rule_id, finding.http_method, finding.http_path)
            if finding.engine == "zap" and key in assessed:
                detected.add(key)
                observed_cwes[key].update(getattr(finding, "cwe_ids", ()))
            else:
                unassessed += 1
    results: list[DastCaseResult] = []
    for case in manifest.cases:
        key = (case.mode, case.rule_id, case.method, case.path)
        found = key in detected
        cwe_match = case.cwe_id in observed_cwes[key] if found else None
        outcome: Literal["TP", "FP", "FN", "TN"] = (
            "TP" if case.expected and found else "FN" if case.expected else "FP" if found else "TN"
        )
        results.append(
            DastCaseResult(
                case.id,
                case.mode,
                case.method,
                case.path,
                case.rule_id,
                case.cwe_id,
                case.expected,
                found,
                cwe_match,
                outcome,
                proof_deltas[case.id],
            )
        )
    case_tuple = tuple(results)
    rules = tuple(
        (rule_id, _metrics(tuple(case for case in case_tuple if case.rule_id == rule_id)))
        for rule_id in sorted({case.rule_id for case in case_tuple})
    )
    return DastBenchmarkResult(
        manifest.name,
        manifest.sha256,
        manifest.provenance,
        fixture_image_id,
        source_revision,
        source_dirty,
        passive.version,
        passive.elapsed_ms,
        active.elapsed_ms,
        total_elapsed_ms,
        case_tuple,
        rules,
        _metrics(case_tuple),
        unassessed,
        sum(case.cwe_match is False for case in case_tuple),
    )


def render_benchmark_json(result: DastBenchmarkResult) -> str:
    """Render only bounded assessment metadata and normalized counts."""

    return json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def render_benchmark_markdown(result: DastBenchmarkResult) -> str:
    """Human-readable author-written regression evidence."""

    totals = result.metrics
    lines = [
        "# Disposable API DAST benchmark",
        "",
        "This author-written regression corpus does not estimate performance on arbitrary APIs.",
        "",
        f"- Manifest SHA-256: `{result.manifest_sha256}`",
        f"- Fixture image ID: `{result.fixture_image_id}`",
        f"- Source revision: `{result.source_revision}`",
        f"- Source dirty: `{str(result.source_dirty).lower()}`",
        f"- ZAP image: `{result.zap_version}`",
        f"- Cases scored: {len(result.cases)}/{len(result.cases)}",
        f"- TP/FP/FN/TN: {totals.tp}/{totals.fp}/{totals.fn}/{totals.tn}",
        f"- Unassessed normalized findings: {result.unassessed_findings}",
        f"- CWE metadata mismatch cases: {result.cwe_mismatch_cases}",
        f"- Passive elapsed ms: {result.passive_elapsed_ms}",
        f"- Active elapsed ms: {result.active_elapsed_ms}",
        f"- Total elapsed ms: {result.total_elapsed_ms}",
        "",
        "| Rule | TP | FP | FN | TN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rule, metrics in result.rules:
        rates = [
            "n/a" if value is None else f"{value:.3f}"
            for value in (metrics.precision, metrics.recall, metrics.f1)
        ]
        lines.append(
            f"| {rule} | {metrics.tp} | {metrics.fp} | {metrics.fn} | {metrics.tn} | "
            f"{' | '.join(rates)} |"
        )
    lines.extend(
        [
            "",
            "| Case | Mode | Rule | Path | Expected | Detected | Outcome | Proof delta |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for case in result.cases:
        lines.append(
            f"| {case.id} | {case.mode} | {case.rule_id} | {case.path} | "
            f"{str(case.expected).lower()} | "
            f"{str(case.detected).lower()} | {case.outcome} | {case.proof_delta} |"
        )
    lines.extend(
        [
            "",
            "Unassessed counts include only normalized findings, not all raw ZAP alerts.",
            "Per-rule timing is unavailable because rules share the same scan invocation.",
            "",
        ]
    )
    return "\n".join(lines)
