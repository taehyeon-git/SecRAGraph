"""Per-rule benign rates use only files on which that rule can run."""

from __future__ import annotations

from security_review.evaluation.scanner_benchmark import (
    assess_scanner_case,
    summarize_scanner_assessments,
)
from security_review.evaluation.scanner_models import ScannerCase


def _benign(case_id: str, file_path: str) -> ScannerCase:
    return ScannerCase(
        case_id=case_id,
        file_path=file_path,
        source="synthetic benign content\n",
        expected=frozenset(),
        is_benign=True,
    )


def test_rule_benign_denominators_follow_supported_extensions() -> None:
    cases = (
        _benign("python", "nested/sample.py"),
        _benign("yaml", "config/settings.yaml"),
        _benign("env", "config/.env"),
        _benign("typescript", "web/index.ts"),
    )
    assessments = [
        assess_scanner_case(
            case,
            frozenset({("PY001", 1)}) if case.case_id == "python" else frozenset(),
            (),
        )
        for case in cases
    ]

    result = summarize_scanner_assessments(
        assessments,
        corpus_sha256="0" * 64,
        rule_set_version="test",
    )
    by_rule = dict(result.by_rule)

    assert result.metrics.eligible_benign_cases == 4
    assert result.metrics.benign_false_alarm_cases == 1
    assert by_rule["PY001"].eligible_benign_cases == 1
    assert by_rule["PY001"].benign_false_alarm_cases == 1
    assert by_rule["PY001"].benign_false_alarm_rate == 1.0
    assert by_rule["PY002"].eligible_benign_cases == 1
    assert by_rule["JS001"].eligible_benign_cases == 2
    assert by_rule["JS001"].benign_false_alarm_cases == 0
    assert by_rule["SEC001"].eligible_benign_cases == 4
