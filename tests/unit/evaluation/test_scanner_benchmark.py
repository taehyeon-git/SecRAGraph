"""Contracts for the synthetic scanner corpus and its public scan-path runner."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.run_scanner_benchmark import main
from security_review.evaluation import scanner_benchmark as benchmark_module
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


def test_fixed_corpus_has_three_same_format_pairs_for_every_planned_rule() -> None:
    corpus_path = Path(__file__).resolve().parents[3] / "data/evaluation/scanner_cases.json"
    cases = load_scanner_cases(corpus_path)
    by_id = {case.case_id: case for case in cases}
    planned_rules = {"PY001", "PY002", "PY003", "PY004", "SEC001", "JS001"}

    assert len(cases) == 39
    for rule_id in planned_rules:
        positives = [case for case in cases if any(label[0] == rule_id for label in case.expected)]
        assert len(positives) >= 3, rule_id
        for positive in positives:
            assert positive.case_id.endswith("-positive")
            assert len(positive.expected) == 1
            negative_id = positive.case_id.removesuffix("-positive") + "-negative"
            negative = by_id[negative_id]
            assert negative.file_path == positive.file_path, positive.case_id
            assert negative.source != positive.source
            assert negative.is_benign and not negative.expected
            assert not negative.unassessed_rules


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


def test_manifest_line_endings_do_not_change_corpus_digest_or_evidence(tmp_path: Path) -> None:
    manifest = json.dumps({"schema_version": 1, "cases": [_case()]}, indent=2) + "\n"
    lf_path = tmp_path / "lf.json"
    crlf_path = tmp_path / "crlf.json"
    lf_path.write_bytes(manifest.encode("utf-8"))
    crlf_path.write_bytes(manifest.replace("\n", "\r\n").encode("utf-8"))
    assert lf_path.read_bytes() != crlf_path.read_bytes()

    lf_result = run_scanner_benchmark(lf_path)
    crlf_result = run_scanner_benchmark(crlf_path)
    expected_digest = sha256(lf_path.read_bytes()).hexdigest()

    assert lf_result.corpus_sha256 == crlf_result.corpus_sha256 == expected_digest
    assert lf_result.to_json().encode("utf-8") == crlf_result.to_json().encode("utf-8")
    assert lf_result.to_markdown().encode("utf-8") == crlf_result.to_markdown().encode("utf-8")


def test_current_revision_uses_absolute_git_and_bounded_read_only_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: str(Path("tools/git")))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "a" * 40 + "\n", "")

    monkeypatch.setattr(subprocess, "run", run)

    assert benchmark_module._current_revision() == "a" * 40
    assert len(calls) == 1
    args, options = calls[0]
    assert args == [str(Path("tools/git").resolve()), "rev-parse", "--verify", "HEAD"]
    assert options["cwd"] == benchmark_module._REPOSITORY_ROOT
    assert options["check"] is True
    assert options["capture_output"] is True
    assert options["text"] is True
    assert options["shell"] is False
    assert isinstance(options["timeout"], (int, float))
    assert 0 < options["timeout"] <= 5


def test_current_revision_reports_unavailable_without_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    assert benchmark_module._current_revision() == "unavailable"


@pytest.mark.parametrize(
    "failure",
    [
        OSError("git cannot start"),
        subprocess.CalledProcessError(128, ["git", "rev-parse", "--verify", "HEAD"]),
        subprocess.TimeoutExpired(["git", "rev-parse", "--verify", "HEAD"], 5),
    ],
)
def test_current_revision_reports_unavailable_when_git_fails(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: str(Path("tools/git").resolve()))

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(subprocess, "run", fail)

    assert benchmark_module._current_revision() == "unavailable"


def test_default_command_writes_stable_final_corpus_evidence(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[3]
    outputs = (tmp_path / "first", tmp_path / "second")
    for output in outputs:
        command = subprocess.run(  # noqa: S603 - fixed local Python module and output path
            [sys.executable, "-m", "scripts.run_scanner_benchmark", "--output-dir", str(output)],
            cwd=repository_root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert command.returncode == 0, command.stderr + command.stdout

    first_json = (outputs[0] / "scanner.json").read_bytes()
    first_markdown = (outputs[0] / "scanner.md").read_bytes()
    assert first_json == (outputs[1] / "scanner.json").read_bytes()
    assert first_markdown == (outputs[1] / "scanner.md").read_bytes()
    payload = json.loads(first_json)
    assert (
        first_json.decode("utf-8")
        == json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    )
    assert payload["rule_set_version"] == "2026.10.2"
    assert "Rule set version: `2026.10.2`" in first_markdown.decode("utf-8")
    assert "scan_id" not in payload and "created_at" not in payload
    assert payload["corpus_sha256"] == (
        "6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d"
    )
    assert payload["scanner_base_revision"] == "ac88e9f"
    assert payload["coverage"] == {
        "total": 39,
        "scanned": 39,
        "skipped": 0,
        "parse_warnings": 0,
        "expected_diagnostics": 0,
        "unexpected_diagnostics": 0,
        "missing_diagnostics": 0,
    }
    assert len(payload["cases"]) == 39
    assert [case["case_id"] for case in payload["cases"]] == sorted(
        case["case_id"] for case in payload["cases"]
    )
    assert (payload["metrics"]["tp"], payload["metrics"]["fp"], payload["metrics"]["fn"]) == (
        18,
        0,
        0,
    )
    assert payload["metrics"]["precision_denominator"] == 18
    assert payload["metrics"]["recall_denominator"] == 18
    assert payload["metrics"]["eligible_benign_cases"] == 21
    assert payload["metrics"]["benign_false_alarm_cases"] == 0
    assert list(payload["by_rule"]) == ["JS001", "PY001", "PY002", "PY003", "PY004", "SEC001"]
    for metrics in payload["by_rule"].values():
        assert (metrics["tp"], metrics["fp"], metrics["fn"]) == (3, 0, 0)
        assert metrics["precision_denominator"] == 3
        assert metrics["recall_denominator"] == 3


def test_expected_python_syntax_diagnostic_is_not_eligible_benign(tmp_path: Path) -> None:
    path = _manifest(
        tmp_path,
        [
            _case(
                source="if (\n",
                expected_diagnostics=["python_syntax_error"],
            )
        ],
    )

    result = run_scanner_benchmark(path)

    assert result.coverage.scanned == 1
    assert result.coverage.parse_warnings == 1
    assert result.coverage.expected_diagnostics == 1
    assert result.coverage.unexpected_diagnostics == 0
    assert result.metrics.eligible_benign_cases == 0
    assert result.metrics.benign_false_alarm_rate is None
    assert result.cases[0].eligible_benign is False


def test_cli_enforce_fails_altered_label_and_baseline_records_it(tmp_path: Path) -> None:
    path = _manifest(
        tmp_path,
        [
            _case(
                source="value = 1\neval(user_input)\n",
                expected=[{"rule_id": "PY001", "line_start": 1}],
                is_benign=False,
            )
        ],
    )
    output = tmp_path / "output"

    assert main(["--cases", str(path), "--output-dir", str(output)]) == 1
    assert main(["--cases", str(path), "--output-dir", str(output), "--baseline"]) == 0
    payload = json.loads((output / "scanner.json").read_text(encoding="utf-8"))
    assert payload["metrics"]["fp"] == 1
    assert payload["metrics"]["fn"] == 1
    assert payload["cases"][0]["unexpected_findings"] == [["sample", "PY001", 2]]
    assert payload["cases"][0]["missing_findings"] == [["sample", "PY001", 1]]
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
    assert main(["--cases", str(path), "--output-dir", str(tmp_path / "strict")]) == 1
    assert main(["--cases", str(path), "--output-dir", str(tmp_path / "out"), "--baseline"]) == 1
