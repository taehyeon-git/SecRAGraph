"""Exact-match metrics from the public, non-executing scanner path."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from security_review.application import scan_path
from security_review.evaluation.scanner_models import FindingKey, ScannerCase, load_scanner_cases
from security_review.scanner.files import ScanLimits
from security_review.scanner.rules import DEFAULT_RULES

SCANNER_BASE_REVISION = "ac88e9f"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_SKIP_REASONS = frozenset(
    {
        "binary_or_invalid_utf8",
        "candidate_limit_exceeded",
        "file_changed_or_unreadable",
        "file_too_large",
        "max_files_exceeded",
        "outside_root",
        "processing_time_limit_exceeded",
        "symlink",
        "unreadable",
        "unsupported_extension",
    }
)


@dataclass(frozen=True, slots=True)
class ScannerMetrics:
    """Finding counts plus rates with visible denominators."""

    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None
    eligible_benign_cases: int
    benign_false_alarm_cases: int
    benign_false_alarm_rate: float | None

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
            "f1_denominator": (
                None
                if self.precision is None or self.recall is None
                else self.precision + self.recall
            ),
            "eligible_benign_cases": self.eligible_benign_cases,
            "benign_false_alarm_cases": self.benign_false_alarm_cases,
            "benign_false_alarm_rate": self.benign_false_alarm_rate,
            "benign_false_alarm_denominator": self.eligible_benign_cases,
        }


def score_findings(
    expected: frozenset[FindingKey],
    actual: frozenset[FindingKey],
    eligible_benign_case_ids: frozenset[str],
) -> ScannerMetrics:
    """Score distinct (case, rule, line) keys without fuzzy line matching."""

    tp = len(expected & actual)
    fp = len(actual - expected)
    fn = len(expected - actual)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    false_alarm_cases = len(
        {case_id for case_id, _, _ in actual if case_id in eligible_benign_case_ids}
    )
    benign_count = len(eligible_benign_case_ids)
    return ScannerMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        eligible_benign_cases=benign_count,
        benign_false_alarm_cases=false_alarm_cases,
        benign_false_alarm_rate=false_alarm_cases / benign_count if benign_count else None,
    )


@dataclass(frozen=True, slots=True)
class CaseAssessment:
    case_id: str
    file_path: str
    expected_findings: frozenset[FindingKey]
    actual_findings: frozenset[FindingKey]
    missing_findings: frozenset[FindingKey]
    unexpected_findings: frozenset[FindingKey]
    unassessed_findings: frozenset[FindingKey]
    expected_diagnostics: tuple[str, ...]
    actual_diagnostics: tuple[str, ...]
    missing_diagnostics: tuple[str, ...]
    unexpected_diagnostics: tuple[str, ...]
    unassessed_rules: frozenset[str]
    eligible_benign: bool
    scanned: bool
    skipped: bool
    parse_warning: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "file_path": self.file_path,
            "expected_findings": [list(key) for key in sorted(self.expected_findings)],
            "actual_findings": [list(key) for key in sorted(self.actual_findings)],
            "missing_findings": [list(key) for key in sorted(self.missing_findings)],
            "unexpected_findings": [list(key) for key in sorted(self.unexpected_findings)],
            "unassessed_findings": [list(key) for key in sorted(self.unassessed_findings)],
            "expected_diagnostics": list(self.expected_diagnostics),
            "actual_diagnostics": list(self.actual_diagnostics),
            "missing_diagnostics": list(self.missing_diagnostics),
            "unexpected_diagnostics": list(self.unexpected_diagnostics),
            "unassessed_rules": sorted(self.unassessed_rules),
            "eligible_benign": self.eligible_benign,
            "scanned": self.scanned,
            "skipped": self.skipped,
            "parse_warning": self.parse_warning,
        }


def _diagnostic_code(warning: str, file_path: str) -> str:
    leaf = Path(file_path).name
    prefix = f"{leaf}:"
    return warning[len(prefix) :] if warning.startswith(prefix) else warning


def assess_scanner_case(
    case: ScannerCase,
    actual: frozenset[tuple[str, int]],
    warnings: tuple[str, ...],
) -> CaseAssessment:
    """Separate assessment gaps from scored rules, including parse diagnostics."""

    expected_findings = frozenset(
        (case.case_id, rule_id, line_start) for rule_id, line_start in case.expected
    )
    all_actual = frozenset((case.case_id, rule_id, line_start) for rule_id, line_start in actual)
    unassessed = frozenset(key for key in all_actual if key[1] in case.unassessed_rules)
    actual_findings = all_actual - unassessed
    actual_diagnostics = tuple(_diagnostic_code(warning, case.file_path) for warning in warnings)
    missing_diagnostics = tuple(
        code for code in case.expected_diagnostics if code not in actual_diagnostics
    )
    unexpected_diagnostics = tuple(
        code for code in actual_diagnostics if code not in case.expected_diagnostics
    )
    skipped = any(code in _SKIP_REASONS for code in actual_diagnostics)
    return CaseAssessment(
        case_id=case.case_id,
        file_path=case.file_path,
        expected_findings=expected_findings,
        actual_findings=actual_findings,
        missing_findings=expected_findings - actual_findings,
        unexpected_findings=actual_findings - expected_findings,
        unassessed_findings=unassessed,
        expected_diagnostics=case.expected_diagnostics,
        actual_diagnostics=actual_diagnostics,
        missing_diagnostics=missing_diagnostics,
        unexpected_diagnostics=unexpected_diagnostics,
        unassessed_rules=case.unassessed_rules,
        eligible_benign=(
            case.is_benign
            and not case.unassessed_rules
            and not skipped
            and not missing_diagnostics
            and not unexpected_diagnostics
        ),
        scanned=not skipped,
        skipped=skipped,
        parse_warning="python_syntax_error" in actual_diagnostics,
    )


@dataclass(frozen=True, slots=True)
class ScannerCoverage:
    total: int
    scanned: int
    skipped: int
    parse_warnings: int
    expected_diagnostics: int
    unexpected_diagnostics: int
    missing_diagnostics: int

    def to_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "scanned": self.scanned,
            "skipped": self.skipped,
            "parse_warnings": self.parse_warnings,
            "expected_diagnostics": self.expected_diagnostics,
            "unexpected_diagnostics": self.unexpected_diagnostics,
            "missing_diagnostics": self.missing_diagnostics,
        }


def _rate(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


@dataclass(frozen=True, slots=True)
class ScannerBenchmark:
    """Stable projection of scanner reports and explicit coverage failures."""

    cases: tuple[CaseAssessment, ...]
    metrics: ScannerMetrics
    by_rule: tuple[tuple[str, ScannerMetrics], ...]
    coverage: ScannerCoverage
    corpus_sha256: str
    scanner_base_revision: str
    current_revision: str

    @property
    def expected_diagnostics(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (case.case_id, code) for case in self.cases for code in case.expected_diagnostics
        )

    @property
    def unexpected_diagnostics(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (case.case_id, code) for case in self.cases for code in case.unexpected_diagnostics
        )

    @property
    def has_finding_mismatches(self) -> bool:
        return any(case.missing_findings or case.unexpected_findings for case in self.cases)

    @property
    def has_coverage_failures(self) -> bool:
        return bool(
            self.coverage.skipped
            or self.coverage.unexpected_diagnostics
            or self.coverage.missing_diagnostics
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "benchmark": "small, author-created synthetic scanner corpus",
            "corpus_sha256": self.corpus_sha256,
            "scanner_base_revision": self.scanner_base_revision,
            "current_revision": self.current_revision,
            "coverage": self.coverage.to_dict(),
            "metrics": self.metrics.to_dict(),
            "by_rule": {rule_id: metrics.to_dict() for rule_id, metrics in self.by_rule},
            "expected_diagnostics": [list(item) for item in self.expected_diagnostics],
            "unexpected_diagnostics": [list(item) for item in self.unexpected_diagnostics],
            "cases": [case.to_dict() for case in self.cases],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    def to_markdown(self) -> str:
        lines = [
            "# Scanner benchmark",
            "",
            "Small, author-created synthetic corpus; these rates do not estimate performance "
            "on arbitrary repositories.",
            "",
            f"- Corpus SHA-256: `{self.corpus_sha256}`",
            f"- Scanner baseline revision: `{self.scanner_base_revision}`",
            f"- Current revision: `{self.current_revision}`",
            f"- Coverage: {self.coverage.scanned}/{self.coverage.total} scanned; "
            f"{self.coverage.skipped} skipped; {self.coverage.parse_warnings} parse warnings; "
            f"{self.coverage.expected_diagnostics} expected diagnostics; "
            f"{self.coverage.unexpected_diagnostics} unexpected diagnostics; "
            f"{self.coverage.missing_diagnostics} missing diagnostics",
            "",
            "| Rule | TP | FP | FN | Precision (TP+FP) | Recall (TP+FN) | F1 | "
            "Benign alarms / eligible cases |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for rule_id, metrics in (("Overall", self.metrics), *self.by_rule):
            lines.append(
                f"| {rule_id} | {metrics.tp} | {metrics.fp} | {metrics.fn} | "
                f"{_rate(metrics.precision)} ({metrics.tp + metrics.fp}) | "
                f"{_rate(metrics.recall)} ({metrics.tp + metrics.fn}) | "
                f"{_rate(metrics.f1)} | "
                f"{metrics.benign_false_alarm_cases}/{metrics.eligible_benign_cases} "
                f"({_rate(metrics.benign_false_alarm_rate)}) |"
            )
        lines.extend(["", "## Mismatches and diagnostics", ""])
        for case in self.cases:
            if (
                case.missing_findings
                or case.unexpected_findings
                or case.missing_diagnostics
                or case.unexpected_diagnostics
                or case.skipped
            ):
                lines.append(
                    f"- `{case.case_id}`: FP={list(sorted(case.unexpected_findings))}; "
                    f"FN={list(sorted(case.missing_findings))}; "
                    f"missing diagnostics={list(case.missing_diagnostics)}; "
                    f"unexpected diagnostics={list(case.unexpected_diagnostics)}; "
                    f"skipped={case.skipped}"
                )
        if lines[-1] == "":
            lines.append("- None")
        return "\n".join(lines) + "\n"


def _current_revision() -> str:
    result = subprocess.run(  # noqa: S603 - fixed read-only git command, no shell
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=_REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def run_scanner_benchmark(cases_path: Path) -> ScannerBenchmark:
    """Materialize each case alone and invoke the application's real scan path."""

    corpus_sha256 = sha256(cases_path.read_bytes()).hexdigest()
    cases = load_scanner_cases(cases_path)
    assessments: list[CaseAssessment] = []
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="scanner-case-") as directory:
            materialized = Path(directory, case.file_path)
            materialized.parent.mkdir(parents=True, exist_ok=True)
            materialized.write_text(case.source, encoding="utf-8", newline="")
            report = scan_path(materialized, ScanLimits(), target_name=case.case_id)
        actual_labels = frozenset((item.rule_id, item.line_start) for item in report.findings)
        assessments.append(assess_scanner_case(case, actual_labels, report.warnings))

    assessed = tuple(assessments)
    expected = frozenset(key for case in assessed for key in case.expected_findings)
    actual_keys = frozenset(key for case in assessed for key in case.actual_findings)
    eligible = frozenset(case.case_id for case in assessed if case.eligible_benign)
    rule_ids = sorted(
        {rule.rule_id for rule in DEFAULT_RULES}
        | {key[1] for key in expected}
        | {key[1] for key in actual_keys}
    )
    by_rule = tuple(
        (
            rule_id,
            score_findings(
                frozenset(key for key in expected if key[1] == rule_id),
                frozenset(key for key in actual_keys if key[1] == rule_id),
                eligible,
            ),
        )
        for rule_id in rule_ids
    )
    coverage = ScannerCoverage(
        total=len(assessed),
        scanned=sum(case.scanned for case in assessed),
        skipped=sum(case.skipped for case in assessed),
        parse_warnings=sum(case.parse_warning for case in assessed),
        expected_diagnostics=sum(len(case.expected_diagnostics) for case in assessed),
        unexpected_diagnostics=sum(len(case.unexpected_diagnostics) for case in assessed),
        missing_diagnostics=sum(len(case.missing_diagnostics) for case in assessed),
    )
    return ScannerBenchmark(
        cases=assessed,
        metrics=score_findings(expected, actual_keys, eligible),
        by_rule=by_rule,
        coverage=coverage,
        corpus_sha256=corpus_sha256,
        scanner_base_revision=SCANNER_BASE_REVISION,
        current_revision=_current_revision(),
    )
