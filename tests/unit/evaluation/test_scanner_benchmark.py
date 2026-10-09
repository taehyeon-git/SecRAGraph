"""Contracts for the synthetic scanner corpus and its public scan-path runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_scanner_benchmark import main
from security_review.evaluation.scanner_benchmark import (
    assess_scanner_case,
    run_scanner_benchmark,
    score_findings,
)
from security_review.evaluation.scanner_models import ScannerCase, load_scanner_cases
from security_review.reporting.builder import build_report


def _manifest(tmp_path: Path, cases: list[dict[str, object]]) -> Path:
    path = tmp_path / "cases.json"
    path.write_text(json.dumps({"schema_version": 1, "cases": cases}), encoding="utf-8")
    return path


def _case(
    case_id: str = "sample",
    *,
    file_path: str = "sample.py",
    source: str = "value = 1\n",
    expected: list[dict[str, object]] | None = None,
    is_benign: bool = True,
    expected_diagnostics: list[str] | None = None,
    unassessed_rules: list[str] | None = None,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "file_path": file_path,
        "source": source,
        "expected": expected or [],
        "is_benign": is_benign,
        "expected_diagnostics": expected_diagnostics or [],
        "unassessed_rules": unassessed_rules or [],
    }


def test_exact_match_scoring_counts_wrong_line_as_fp_and_fn() -> None:
    result = score_findings(
        frozenset({("positive", "PY001", 2), ("missed", "PY002", 4)}),
        frozenset({("positive", "PY001", 2), ("missed", "PY002", 5), ("benign", "PY003", 1)}),
        frozenset({"benign"}),
    )

    assert (result.tp, result.fp, result.fn) == (1, 2, 1)
    assert (result.precision, result.recall, result.f1) == (1 / 3, 1 / 2, 0.4)
    assert (result.benign_false_alarm_cases, result.eligible_benign_cases) == (1, 1)
    assert result.benign_false_alarm_rate == 1.0


def test_zero_denominators_are_na_and_benign_rate_counts_cases() -> None:
    empty = score_findings(frozenset(), frozenset(), frozenset())
    assert (empty.precision, empty.recall, empty.f1, empty.benign_false_alarm_rate) == (
        None,
        None,
        None,
        None,
    )

    alarms = score_findings(
        frozenset(),
        frozenset({("first", "PY001", 1), ("first", "PY002", 2)}),
        frozenset({"first", "second"}),
    )
    assert (alarms.tp, alarms.fp, alarms.fn) == (0, 2, 0)
    assert alarms.precision == 0.0
    assert alarms.recall is None
    assert alarms.f1 is None
    assert alarms.benign_false_alarm_rate == 0.5


@pytest.mark.parametrize(
    ("cases", "error"),
    [
        ([_case("same"), _case("same")], "duplicate case_id"),
        (
            [
                _case(
                    expected=[
                        {"rule_id": "PY001", "line_start": 1},
                        {"rule_id": "PY001", "line_start": 1},
                    ],
                    is_benign=False,
                )
            ],
            "duplicate label",
        ),
        ([_case(is_benign=False)], "is_benign"),
        ([_case(file_path="../outside.py")], "file_path"),
        ([_case(file_path="unsupported.txt")], "extension"),
        ([_case(source=" \n ")], "blank"),
        ([_case(source="x" * 1_000_001)], "too large"),
        (
            [_case(expected=[{"rule_id": "bad id", "line_start": 1}], is_benign=False)],
            "rule_id",
        ),
        (
            [_case(expected=[{"rule_id": "PY001", "line_start": 0}], is_benign=False)],
            "line_start",
        ),
    ],
)
def test_manifest_rejects_invalid_cases(
    tmp_path: Path, cases: list[dict[str, object]], error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        load_scanner_cases(_manifest(tmp_path, cases))


def test_manifest_accepts_future_rule_label_without_current_registry(tmp_path: Path) -> None:
    cases = load_scanner_cases(
        _manifest(
            tmp_path,
            [
                _case(
                    source="yaml.unsafe_load(data)\n",
                    expected=[{"rule_id": "PY004", "line_start": 1}],
                    is_benign=False,
                )
            ],
        )
    )
    assert cases[0].expected == frozenset({("PY004", 1)})


def test_expected_parse_diagnostic_keeps_secret_label_and_excludes_benign_case() -> None:
    positive = ScannerCase(
        case_id="syntax-secret",
        file_path="sample.py",
        source='API_KEY="synthetic-only-123456"\nif (\n',
        expected=frozenset({("SEC001", 1)}),
        is_benign=False,
        expected_diagnostics=("python_syntax_error",),
        unassessed_rules=frozenset({"PY001", "PY002", "PY003", "PY004"}),
    )
    benign = ScannerCase(
        case_id="syntax-benign",
        file_path="sample.py",
        source="if (\n",
        expected=frozenset(),
        is_benign=True,
        expected_diagnostics=("python_syntax_error",),
        unassessed_rules=frozenset({"PY001", "PY002", "PY003", "PY004"}),
    )

    assessed_positive = assess_scanner_case(
        positive,
        frozenset({("SEC001", 1)}),
        ("python_syntax_error",),
    )
    assessed_benign = assess_scanner_case(benign, frozenset(), ("python_syntax_error",))

    assert assessed_positive.expected_findings == frozenset({("syntax-secret", "SEC001", 1)})
    assert assessed_positive.actual_findings == assessed_positive.expected_findings
    assert assessed_positive.expected_diagnostics == ("python_syntax_error",)
    assert assessed_positive.unexpected_diagnostics == ()
    assert assessed_benign.eligible_benign is False


def test_real_scan_path_exposes_exact_findings_and_coverage(tmp_path: Path) -> None:
    path = _manifest(
        tmp_path,
        [
            _case(
                "positive",
                source="result = eval(user_input)\n",
                expected=[{"rule_id": "PY001", "line_start": 1}],
                is_benign=False,
            ),
            _case("negative", source="result = ast.literal_eval(user_input)\n"),
        ],
    )

    result = run_scanner_benchmark(path)

    assert (result.coverage.scanned, result.coverage.skipped, result.coverage.parse_warnings) == (
        2,
        0,
        0,
    )
    assert (result.metrics.tp, result.metrics.fp, result.metrics.fn) == (1, 0, 0)
    assert (result.metrics.eligible_benign_cases, result.metrics.benign_false_alarm_cases) == (
        1,
        0,
    )
    assert result.unexpected_diagnostics == ()


def test_two_real_runs_render_identical_bytes_without_report_uuid_or_time(tmp_path: Path) -> None:
    path = _manifest(tmp_path, [_case()])

    first = run_scanner_benchmark(path)
    second = run_scanner_benchmark(path)

    assert first.to_json() == second.to_json()
    assert first.to_markdown() == second.to_markdown()
    assert "scan_id" not in first.to_json()
    assert "created_at" not in first.to_json()
    assert first.corpus_sha256 == second.corpus_sha256


def test_cli_enforce_fails_mismatch_and_baseline_records_it(tmp_path: Path) -> None:
    path = _manifest(tmp_path, [_case(source="eval(user_input)\n")])
    output = tmp_path / "output"

    assert main(["--cases", str(path), "--output-dir", str(output)]) == 1
    assert main(["--cases", str(path), "--output-dir", str(output), "--baseline"]) == 0
    payload = json.loads((output / "scanner.json").read_text(encoding="utf-8"))
    assert payload["metrics"]["fp"] == 1
    assert payload["cases"][0]["unexpected_findings"] == [["sample", "PY001", 1]]
    assert (output / "scanner.md").is_file()


@pytest.mark.parametrize("warning", ["surprise", "sample.py:file_too_large"])
def test_baseline_still_rejects_unexpected_warning_or_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, warning: str
) -> None:
    import security_review.evaluation.scanner_benchmark as benchmark_module

    path = _manifest(tmp_path, [_case()])
    monkeypatch.setattr(
        benchmark_module,
        "scan_path",
        lambda *_args, **_kwargs: build_report("sample.py", (), warnings=(warning,)),
    )

    result = run_scanner_benchmark(path)
    assert result.coverage.skipped == int("file_too_large" in warning)
    assert result.unexpected_diagnostics
    assert main(["--cases", str(path), "--output-dir", str(tmp_path / "out"), "--baseline"]) == 1
