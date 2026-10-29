"""Contract tests for the Compose-only benchmark evidence gate."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from hashlib import sha256
from pathlib import Path

import pytest

from security_review.evaluation.multiengine_benchmark import load_labeled_corpus

_ROOT = Path(__file__).resolve().parents[3]
_CASES = _ROOT / "data/evaluation/multiengine_cases.json"
_RULES = (
    "COMPOSE/PRIVILEGED",
    "COMPOSE/HOST_NETWORK",
    "COMPOSE/HOST_PID",
    "COMPOSE/HOST_IPC",
    "COMPOSE/CAP_ADD_DANGEROUS",
    "COMPOSE/UNCONFINED_PROFILE",
    "COMPOSE/DOCKER_SOCKET",
    "COMPOSE/HOST_ROOT_MOUNT",
    "COMPOSE/EXPLICIT_ROOT_USER",
    "COMPOSE/PROVIDER",
)


def _assessment(rule: str, case: str, *, tp: int = 0, fp: int = 0, fn: int = 0) -> dict:
    return {
        "case_id": case,
        "engine": "compose-policy",
        "rule_id": rule,
        "file_path": "compose.yaml",
        "status": "scored",
        "reason": None,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "expected_trace": None,
        "trace_status": None,
        "observed_trace": [],
    }


def _metrics(rows: list[dict]) -> dict:
    scored = [row for row in rows if row["status"] == "scored"]
    tp = sum(row["tp"] for row in scored)
    fp = sum(row["fp"] for row in scored)
    fn = sum(row["fn"] for row in scored)
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    f1_denominator = 2 * tp + fp + fn
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / precision_denominator if precision_denominator else None,
        "precision_denominator": precision_denominator,
        "recall": tp / recall_denominator if recall_denominator else None,
        "recall_denominator": recall_denominator,
        "f1": 2 * tp / f1_denominator if f1_denominator else None,
        "assessments_scored": len(scored),
    }


def _refresh(evidence: dict) -> None:
    assessments = evidence["assessments"]
    by_rule: dict[str, list[dict]] = defaultdict(list)
    by_engine: dict[str, list[dict]] = defaultdict(list)
    for row in assessments:
        by_rule[f"{row['engine']}:{row['rule_id']}"].append(row)
        by_engine[row["engine"]].append(row)
    evidence["by_rule"] = {key: _metrics(rows) for key, rows in by_rule.items()}
    evidence["by_engine"] = {key: _metrics(rows) for key, rows in by_engine.items()}
    evidence["metrics"] = _metrics(assessments)
    evidence["coverage"]["assessments_total"] = len(assessments)
    evidence["coverage"]["assessments_scored"] = sum(
        row["status"] == "scored" for row in assessments
    )
    evidence["coverage"]["assessments_unscored"] = sum(
        row["status"] == "unscored" for row in assessments
    )


def _evidence() -> dict:
    corpus = load_labeled_corpus(_CASES)
    assessments = [
        _assessment(truth.rule_id, case.case_id, tp=len(truth.expected_lines))
        for case in corpus.cases
        for truth in case.assessments
        if truth.engine == "compose-policy"
    ]
    noncompose = corpus.cases[0].assessments[0]
    assessments.append(
        {
            **_assessment(noncompose.rule_id, corpus.cases[0].case_id, fp=2, fn=1),
            "engine": noncompose.engine,
            "file_path": noncompose.file_path,
        }
    )
    compose_cases = {row["case_id"] for row in assessments if row["engine"] == "compose-policy"}
    evidence = {
        "scope": "synthetic_regression",
        "interpretation": (
            "Author-written regression cases; results do not estimate real-world detection."
        ),
        "corpus": {
            "name": corpus.name,
            "manifest_sha256": corpus.manifest_sha256,
            "source_revision": None,
            "ground_truth_sha256": None,
        },
        "coverage": {
            "cases_total": len(corpus.cases),
            "cases_scanned": len(corpus.cases),
            "assessments_total": 0,
            "assessments_scored": 0,
            "assessments_unscored": 0,
            "unassessed_finding_count": 0,
            "traces_expected": 0,
            "traces_scored": 0,
            "traces_verified": 0,
            "traces_unverified": 0,
            "traces_unscored": 0,
        },
        "metrics": {},
        "by_engine": {},
        "by_rule": {},
        "engine_elapsed_ms": {"compose-policy": 12, "opengrep": 3},
        "engine_coverage": {
            "compose-policy": {
                "runs": len(corpus.cases),
                "completed": len(compose_cases),
                "partial": 0,
                "not_run": 0,
                "error": 0,
                "skipped": len(corpus.cases) - len(compose_cases),
                "eligible_files": len(compose_cases),
                "scanned_files": len(compose_cases),
                "elapsed_ms": 12,
            },
            "opengrep": {
                "runs": 1,
                "completed": 1,
                "partial": 0,
                "not_run": 0,
                "error": 0,
                "skipped": 0,
                "eligible_files": 1,
                "scanned_files": 1,
                "elapsed_ms": 3,
            },
        },
        "wall_elapsed_ms": 15,
        "assessments": assessments,
    }
    _refresh(evidence)
    return evidence


def _run(
    tmp_path: Path, evidence: object, *, cases: Path | None = None
) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "multiengine-scanner.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    arguments = [sys.executable, "-m", "scripts.check_compose_evidence", "--evidence", str(path)]
    if cases is not None:
        arguments.extend(("--cases", str(cases)))
    return subprocess.run(  # noqa: S603 - fixed interpreter, module, and controlled path
        arguments,
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _row(assessments: list[dict], case_id: str, rule: str) -> dict:
    return next(row for row in assessments if row["case_id"] == case_id and row["rule_id"] == rule)


def test_valid_compose_evidence_passes_despite_unrelated_fp_fn(tmp_path: Path) -> None:
    result = _run(tmp_path, _evidence())

    assert result.returncode == 0, result.stderr
    assert "compose_evidence_ok" in result.stdout
    assert "assessments=110" in result.stdout


def test_cases_option_uses_selected_manifest_digest(tmp_path: Path) -> None:
    alternate = tmp_path / "cases.json"
    body = _CASES.read_bytes() + b"\n"
    alternate.write_bytes(body)
    evidence = _evidence()
    evidence["corpus"]["manifest_sha256"] = sha256(body).hexdigest()

    default_result = _run(tmp_path, evidence)
    selected_result = _run(tmp_path, evidence, cases=alternate)

    assert default_result.returncode != 0
    assert "manifest_mismatch" in default_result.stderr
    assert selected_result.returncode == 0, selected_result.stderr


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        ("missing_rule", "missing_rules"),
        ("missing_by_rule", "missing_rules"),
        ("unknown_rule", "unexpected_rules"),
        ("no_positive", "missing_positive_coverage"),
        ("omit_benign_case", "assessment_layout_mismatch"),
        ("unscored", "unscored_assessments"),
        ("false_positive", "compose_mismatch"),
        ("false_negative", "compose_mismatch"),
        ("wrong_positive_line_count", "expected_line_count"),
        ("extra_identity", "assessment_layout_mismatch"),
        ("forged_digest", "manifest_mismatch"),
        ("forged_case_coverage", "invalid_case_coverage"),
        ("forged_completed", "invalid_compose_coverage"),
        ("forged_eligible", "invalid_compose_coverage"),
        ("forged_scanned", "invalid_compose_coverage"),
        ("unassessed_finding", "unassessed_findings"),
        ("wrong_scope", "invalid_schema"),
        ("missing_assessments", "invalid_schema"),
        ("malformed_counter", "invalid_schema"),
        ("missing_trace_field", "invalid_schema"),
        ("duplicate_assessment", "invalid_schema"),
        ("summary_disagrees", "invalid_schema"),
        ("summary_rate_disagrees", "invalid_schema"),
    ],
)
def test_gate_rejects_bad_evidence(tmp_path: Path, mutation: str, diagnostic: str) -> None:
    evidence = _evidence()
    assessments = evidence["assessments"]
    if mutation == "missing_rule":
        assessments[:] = [row for row in assessments if row["rule_id"] != _RULES[0]]
        _refresh(evidence)
    elif mutation == "missing_by_rule":
        del evidence["by_rule"][f"compose-policy:{_RULES[0]}"]
    elif mutation == "unknown_rule":
        assessments.append(_assessment("COMPOSE/UNKNOWN", "compose-benign"))
        _refresh(evidence)
    elif mutation == "no_positive":
        _row(assessments, "compose-privileged", _RULES[0])["tp"] = 0
        _refresh(evidence)
    elif mutation == "omit_benign_case":
        assessments[:] = [row for row in assessments if row["case_id"] != "compose-benign"]
        _refresh(evidence)
    elif mutation == "unscored":
        benign = _row(assessments, "compose-benign", _RULES[0])
        benign["status"] = "unscored"
        benign["reason"] = "engine_partial"
        _refresh(evidence)
    elif mutation == "false_positive":
        _row(assessments, "compose-benign", _RULES[0])["fp"] = 1
        _refresh(evidence)
    elif mutation == "false_negative":
        positive = _row(assessments, "compose-privileged", _RULES[0])
        positive["tp"] = 0
        positive["fn"] = 1
        _refresh(evidence)
    elif mutation == "wrong_positive_line_count":
        _row(assessments, "compose-explicit-root-user", "COMPOSE/EXPLICIT_ROOT_USER")["tp"] = 1
        _refresh(evidence)
    elif mutation == "extra_identity":
        assessments.append(_assessment(_RULES[0], "compose-phantom"))
        _refresh(evidence)
    elif mutation == "forged_digest":
        evidence["corpus"]["manifest_sha256"] = "b" * 64
    elif mutation == "forged_case_coverage":
        evidence["coverage"]["cases_total"] -= 1
        evidence["coverage"]["cases_scanned"] -= 1
    elif mutation == "forged_completed":
        evidence["engine_coverage"]["compose-policy"]["completed"] -= 1
    elif mutation == "forged_eligible":
        evidence["engine_coverage"]["compose-policy"]["eligible_files"] -= 1
    elif mutation == "forged_scanned":
        evidence["engine_coverage"]["compose-policy"]["scanned_files"] -= 1
    elif mutation == "unassessed_finding":
        evidence["coverage"]["unassessed_finding_count"] = 1
    elif mutation == "wrong_scope":
        evidence["scope"] = "unlabeled_repository"
    elif mutation == "missing_assessments":
        del evidence["assessments"]
    elif mutation == "malformed_counter":
        _row(assessments, "compose-privileged", _RULES[0])["tp"] = True
    elif mutation == "missing_trace_field":
        del _row(assessments, "compose-privileged", _RULES[0])["expected_trace"]
    elif mutation == "duplicate_assessment":
        assessments.append(dict(_row(assessments, "compose-privileged", _RULES[0])))
        _refresh(evidence)
    elif mutation == "summary_disagrees":
        evidence["by_rule"][f"compose-policy:{_RULES[0]}"]["tp"] = 9
    elif mutation == "summary_rate_disagrees":
        evidence["by_rule"][f"compose-policy:{_RULES[0]}"]["precision_denominator"] = 9

    result = _run(tmp_path, evidence)

    assert result.returncode != 0
    assert diagnostic in result.stderr


def test_gate_rejects_invalid_json_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{bad", encoding="utf-8")
    invalid = subprocess.run(  # noqa: S603 - fixed interpreter, module, and controlled path
        [sys.executable, "-m", "scripts.check_compose_evidence", "--evidence", str(path)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    absent = subprocess.run(  # noqa: S603 - fixed interpreter, module, and controlled path
        [
            sys.executable,
            "-m",
            "scripts.check_compose_evidence",
            "--evidence",
            str(tmp_path / "absent.json"),
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert invalid.returncode != 0 and "invalid_json" in invalid.stderr
    assert absent.returncode != 0 and "unreadable_evidence" in absent.stderr


@pytest.mark.parametrize("invalid_fragment", ['"scope": "other", ', "NaN"])
def test_gate_rejects_noncanonical_json(tmp_path: Path, invalid_fragment: str) -> None:
    body = json.dumps(_evidence())
    if invalid_fragment == "NaN":
        body = body.replace('"precision": 1.0', '"precision": NaN', 1)
    else:
        body = body.replace(
            '"scope": "synthetic_regression", ',
            invalid_fragment + '"scope": "synthetic_regression", ',
            1,
        )
    path = tmp_path / "invalid.json"
    path.write_text(body, encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed interpreter, module, and controlled path
        [sys.executable, "-m", "scripts.check_compose_evidence", "--evidence", str(path)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "invalid_json" in result.stderr


def test_authored_compose_cases_have_one_file_and_complete_rule_labels() -> None:
    corpus = load_labeled_corpus(_ROOT / "data/evaluation/multiengine_cases.json")
    compose_cases = [case for case in corpus.cases if case.case_id.startswith("compose-")]

    assert len(compose_cases) == 11
    assert sum(case.case_id == "compose-benign" for case in compose_cases) == 1
    for case in compose_cases:
        assert len(case.files) == 1
        path, source = case.files[0]
        assert path == "compose.yaml"
        assert {truth.rule_id for truth in case.assessments} == set(_RULES)
        assert all(truth.engine == "compose-policy" for truth in case.assessments)
        assert all(truth.file_path == path for truth in case.assessments)
        assert all(
            1 <= line <= len(source.splitlines())
            for truth in case.assessments
            for line in truth.expected_lines
        )
        positive_count = sum(bool(truth.expected_lines) for truth in case.assessments)
        assert positive_count == (0 if case.case_id == "compose-benign" else 1)
    assert {
        truth.rule_id
        for case in compose_cases
        for truth in case.assessments
        if truth.expected_lines
    } == set(_RULES)
