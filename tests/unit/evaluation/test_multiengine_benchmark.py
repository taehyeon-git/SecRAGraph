import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts import run_multiengine_benchmark
from security_review.domain.models import (
    Confidence,
    Finding,
    ScanExecution,
    Severity,
    TraceLocation,
)
from security_review.evaluation.multiengine_benchmark import (
    EvaluationInputError,
    RuleMetrics,
    evaluate_labeled_corpus,
    load_labeled_corpus,
    measure_unlabeled_repository,
)
from security_review.reporting.builder import build_report
from security_review.scanner.python_flow import PythonFlowAdapter


def _case(case_id: str, source: str, expected: list[int]) -> dict[str, object]:
    return {
        "case_id": case_id,
        "cwe_ids": ["CWE-95"],
        "files": [{"path": "app.py", "source": source}],
        "assessments": [
            {
                "engine": "opengrep",
                "rule_id": "OG/python_eval_rule-eval",
                "file_path": "app.py",
                "expected_lines": expected,
            }
        ],
    }


def _finding(path: str, line: int) -> Finding:
    return Finding(
        id=f"finding-{path}-{line}",
        engine="opengrep",
        rule_id="OG/python_eval_rule-eval",
        category="sast",
        severity=Severity.HIGH,
        file_path=path,
        line_start=line,
        message="Potential issue",
        redacted_evidence="[source omitted]",
        confidence=Confidence.MEDIUM,
        remediation="Review.",
    )


def _report(findings: tuple[Finding, ...], status: str) -> object:
    execution = ScanExecution(
        engine="opengrep",
        kind="sast",
        status=status,  # type: ignore[arg-type]
        elapsed_ms=12,
        eligible_files=("app.py",),
        scanned_files=("app.py",) if status == "completed" else (),
        reason="tool_unavailable" if status == "not_run" else None,
    )
    return build_report("case", findings, executions=(execution,))


def test_labeled_scores_tp_fp_fn_but_excludes_unrun_engine(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "provenance": {"kind": "synthetic", "name": "test fixtures"},
        "cases": [
            _case("positive-found", "x = eval(input())\n", [1]),
            _case("benign-alert", "x = 1\n", []),
            _case("positive-missed", "x = eval(input())\n", [1]),
            _case("positive-unrun", "x = eval(input())\n", [1]),
        ],
    }
    manifest_path = tmp_path / "cases.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    corpus = load_labeled_corpus(manifest_path)
    outcomes = [
        _report((_finding("app.py", 1),), "completed"),
        _report(
            (
                _finding("app.py", 1),
                _finding("app.py", 1).model_copy(
                    update={"id": "unassessed", "rule_id": "OG/other"}
                ),
            ),
            "completed",
        ),
        _report((), "completed"),
        _report((), "not_run"),
    ]
    index = iter(outcomes)

    result = evaluate_labeled_corpus(corpus, lambda _target: next(index), staging_root=tmp_path)
    evidence = result.to_dict()

    assert evidence["scope"] == "synthetic_regression"
    assert evidence["metrics"]["tp"] == 1
    assert evidence["metrics"]["fp"] == 1
    assert evidence["metrics"]["fn"] == 1
    assert evidence["metrics"]["precision"] == 0.5
    assert evidence["metrics"]["recall"] == 0.5
    assert evidence["coverage"]["assessments_scored"] == 3
    assert evidence["coverage"]["assessments_unscored"] == 1
    assert evidence["coverage"]["unassessed_finding_count"] == 1
    assert evidence["by_rule"]["opengrep:OG/python_eval_rule-eval"]["tp"] == 1
    assert evidence["by_engine"]["opengrep"]["fn"] == 1
    assert evidence["engine_coverage"]["opengrep"]["runs"] == 4
    assert evidence["engine_coverage"]["opengrep"]["completed"] == 3
    assert evidence["engine_coverage"]["opengrep"]["not_run"] == 1
    assert evidence["engine_elapsed_ms"]["opengrep"] == 48
    assert "positive-unrun" in result.to_markdown()
    assert "Unassessed findings" in result.to_markdown()
    assert "Engine coverage and time" in result.to_markdown()


def test_unlabeled_measurement_omits_accuracy_metrics(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    measurement = measure_unlabeled_repository(
        tmp_path,
        lambda _target: _report((_finding("app.py", 1),), "completed"),
    )
    payload = measurement.to_dict()

    assert payload["scope"] == "unlabeled_repository"
    assert payload["finding_count"] == 1
    assert payload["engines"]["opengrep"]["status"] == "completed"
    assert "metrics" not in payload
    assert "tp" not in json.dumps(payload)


def test_complete_miss_has_zero_f1_without_inventing_precision() -> None:
    metrics = RuleMetrics(fn=1, assessments_scored=1)
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0


def test_source_to_sink_trace_is_verified_separately_from_detection(tmp_path: Path) -> None:
    case = _case("flow", "user = input()\neval(user)\n", [2])
    case["assessments"][0]["expected_trace"] = {  # type: ignore[index]
        "source_file": "app.py",
        "source_line": 1,
        "sink_file": "app.py",
        "sink_line": 2,
        "required_steps": [{"file": "app.py", "line": 1}],
    }
    manifest = {
        "schema_version": 1,
        "provenance": {"kind": "synthetic", "name": "trace fixtures"},
        "cases": [case],
    }
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    corpus = load_labeled_corpus(path)
    finding = _finding("app.py", 2).model_copy(
        update={
            "trace": (
                TraceLocation(file_path="app.py", line_start=1, role="source"),
                TraceLocation(file_path="app.py", line_start=1, role="step"),
                TraceLocation(file_path="app.py", line_start=2, role="sink"),
            )
        }
    )
    verified = evaluate_labeled_corpus(
        corpus, lambda _target: _report((finding,), "completed"), staging_root=tmp_path
    )
    assert verified.metrics.tp == 1
    assert verified.assessments[0].trace_status == "verified"
    assert verified.to_dict()["coverage"]["traces_verified"] == 1
    assert verified.to_dict()["assessments"][0]["observed_trace"][0] == {
        "role": "source",
        "file_path": "app.py",
        "line_start": 1,
    }

    missing = evaluate_labeled_corpus(
        corpus,
        lambda _target: _report((_finding("app.py", 2),), "completed"),
        staging_root=tmp_path,
    )
    assert missing.metrics.tp == 1
    assert missing.assessments[0].trace_status == "missing"
    assert missing.to_dict()["coverage"]["traces_unverified"] == 1

    wrong_source = finding.model_copy(
        update={
            "trace": (
                TraceLocation(file_path="app.py", line_start=2, role="source"),
                TraceLocation(file_path="app.py", line_start=2, role="sink"),
            )
        }
    )
    mismatched = evaluate_labeled_corpus(
        corpus, lambda _target: _report((wrong_source,), "completed"), staging_root=tmp_path
    )
    assert mismatched.assessments[0].trace_status == "mismatched"

    missing_step = finding.model_copy(
        update={
            "trace": (
                TraceLocation(file_path="app.py", line_start=1, role="source"),
                TraceLocation(file_path="app.py", line_start=2, role="sink"),
            )
        }
    )
    no_relay = evaluate_labeled_corpus(
        corpus, lambda _target: _report((missing_step,), "completed"), staging_root=tmp_path
    )
    assert no_relay.assessments[0].trace_status == "mismatched"


def test_manifest_rejects_outside_paths_and_bad_labels(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "provenance": {"kind": "synthetic", "name": "test fixtures"},
        "cases": [_case("bad-path", "x = 1\n", [2])],
    }
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvaluationInputError, match="label_line_out_of_range"):
        load_labeled_corpus(path)

    manifest["cases"][0]["files"][0]["path"] = "../outside.py"  # type: ignore[index]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvaluationInputError, match="invalid_file_path"):
        load_labeled_corpus(path)


def test_external_corpus_requires_pinned_revision_and_source_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "app.py").write_text("x = eval(input())\n", encoding="utf-8")
    truth = b"file_path,rule_id,line\napp.py,OG/python_eval_rule-eval,1\n"
    (checkout / "truth.csv").write_bytes(truth)
    revision = "a" * 40
    monkeypatch.setattr(
        "security_review.evaluation.multiengine_benchmark._head_revision",
        lambda _path: revision,
    )
    manifest = {
        "schema_version": 1,
        "provenance": {
            "kind": "external",
            "name": "pinned challenge",
            "source_revision": revision,
            "ground_truth_path": "truth.csv",
            "ground_truth_sha256": sha256(truth).hexdigest(),
            "license": "test-only",
        },
        "cases": [
            {
                "case_id": "external-positive",
                "cwe_ids": ["CWE-95"],
                "files": [
                    {
                        "path": "app.py",
                        "sha256": sha256((checkout / "app.py").read_bytes()).hexdigest(),
                    }
                ],
                "assessments": _case("placeholder", "x = 1\n", [1])["assessments"],
            }
        ],
    }
    manifest_path = tmp_path / "external.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    corpus = load_labeled_corpus(manifest_path, checkout=checkout)
    assert corpus.scope == "external_challenge"
    assert corpus.source_revision == revision
    assert corpus.cases[0].cwe_ids == ("CWE-95",)
    evaluation = evaluate_labeled_corpus(
        corpus,
        lambda _target: _report((_finding("app.py", 1),), "completed"),
        staging_root=tmp_path,
    )
    assert "Pinned external challenge" in evaluation.to_markdown()
    assert "Author-written fixtures" not in evaluation.to_markdown()

    (checkout / "app.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(EvaluationInputError, match="case_file_hash_mismatch"):
        load_labeled_corpus(manifest_path, checkout=checkout)


def test_partial_engine_and_ineligible_file_are_unscored(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "provenance": {"kind": "synthetic", "name": "test fixtures"},
        "cases": [_case("partial", "x = eval(input())\n", [1])],
    }
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    corpus = load_labeled_corpus(path)
    result = evaluate_labeled_corpus(
        corpus, lambda _target: _report((), "partial"), staging_root=tmp_path
    )
    assert result.metrics.fn == 0
    assert result.to_dict()["coverage"]["assessments_unscored"] == 1
    assert result.assessments[0].reason == "engine_partial"


def test_runner_writes_evidence_and_requires_complete_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = {
        "schema_version": 1,
        "provenance": {"kind": "synthetic", "name": "test fixtures"},
        "cases": [_case("positive", "x = eval(input())\n", [1])],
    }
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "evidence"
    monkeypatch.setattr(
        run_multiengine_benchmark,
        "_scan",
        lambda _target: _report((_finding("app.py", 1),), "completed"),
    )
    assert (
        run_multiengine_benchmark.main(
            ["--cases", str(cases), "--output-dir", str(output), "--require-complete"]
        )
        == 0
    )
    payload = json.loads((output / "multiengine-scanner.json").read_text(encoding="utf-8"))
    assert payload["coverage"]["assessments_scored"] == 1
    assert "TP" in (output / "multiengine-scanner.md").read_text(encoding="utf-8")

    manifest["cases"][0]["assessments"][0]["expected_trace"] = {  # type: ignore[index]
        "source_file": "app.py",
        "source_line": 1,
        "sink_file": "app.py",
        "sink_line": 1,
    }
    cases.write_text(json.dumps(manifest), encoding="utf-8")
    assert (
        run_multiengine_benchmark.main(
            ["--cases", str(cases), "--output-dir", str(output), "--require-traces"]
        )
        == 1
    )

    monkeypatch.setattr(run_multiengine_benchmark, "_scan", lambda _target: _report((), "not_run"))
    assert (
        run_multiengine_benchmark.main(
            ["--cases", str(cases), "--output-dir", str(output), "--require-complete"]
        )
        == 1
    )


def test_authored_cross_file_cases_match_python_flow_findings_and_traces(tmp_path: Path) -> None:
    manifest = Path(__file__).resolve().parents[3] / "data/evaluation/multiengine_cases.json"
    cases = load_labeled_corpus(manifest).cases
    selected = tuple(case for case in cases if case.case_id.startswith("python-cross-file-"))
    assert len(selected) == 4

    for case in selected:
        root = tmp_path / case.case_id
        for name, source in case.files:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        result = PythonFlowAdapter().scan_snapshot(root, 5.0)
        assert result.execution.status == "completed", case.case_id
        flow_truth = tuple(item for item in case.assessments if item.engine == "python-flow")
        assert len(flow_truth) == 1
        expected = flow_truth[0]
        findings = tuple(
            finding
            for finding in result.findings
            if (finding.rule_id, finding.file_path) == (expected.rule_id, expected.file_path)
        )
        assert {finding.line_start for finding in findings} == expected.expected_lines, case.case_id
        assert len(findings) == len(expected.expected_lines), case.case_id
        assert len(result.findings) == len(findings), case.case_id
        if expected.expected_trace is not None:
            trace = result.findings[0].trace
            assert (trace[0].file_path, trace[0].line_start, trace[0].role) == (
                expected.expected_trace.source_file,
                expected.expected_trace.source_line,
                "source",
            )
            assert (trace[-1].file_path, trace[-1].line_start, trace[-1].role) == (
                expected.expected_trace.sink_file,
                expected.expected_trace.sink_line,
                "sink",
            )
            assert set(expected.expected_trace.required_steps) <= {
                (item.file_path, item.line_start) for item in trace if item.role == "step"
            }
