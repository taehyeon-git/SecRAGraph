"""Require complete, matched Compose labels in multi-engine benchmark JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from security_review.evaluation.multiengine_benchmark import (
    EvaluationInputError,
    LabeledCorpus,
    load_labeled_corpus,
)

_ENGINE = "compose-policy"
_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CASES = _ROOT / "data/evaluation/multiengine_cases.json"
_EXPECTED_COMPOSE_CASES = 11
_RULES = frozenset(
    {
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
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVIDENCE_BYTES = 2_000_000
_COUNT_FIELDS = ("tp", "fp", "fn", "assessments_scored")


class EvidenceError(ValueError):
    """Stable evidence-gate failure code."""


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def _rate_matches(actual: object, expected: float | None) -> bool:
    if expected is None:
        return actual is None
    return type(actual) in (int, float) and actual == expected


def _metric_counts(value: object) -> tuple[int, int, int, int]:
    if not isinstance(value, dict) or not all(
        _nonnegative_int(value.get(field)) for field in _COUNT_FIELDS
    ):
        raise EvidenceError("invalid_schema")
    tp, fp, fn, scored = (value[field] for field in _COUNT_FIELDS)
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    f1_denominator = 2 * tp + fp + fn
    expected_rates = {
        "precision": tp / precision_denominator if precision_denominator else None,
        "recall": tp / recall_denominator if recall_denominator else None,
        "f1": 2 * tp / f1_denominator if f1_denominator else None,
    }
    if (
        value.get("precision_denominator") != precision_denominator
        or value.get("recall_denominator") != recall_denominator
        or not _nonnegative_int(value.get("precision_denominator"))
        or not _nonnegative_int(value.get("recall_denominator"))
        or any(
            not _rate_matches(value.get(name), expected)
            for name, expected in expected_rates.items()
        )
    ):
        raise EvidenceError("invalid_schema")
    return tp, fp, fn, scored


def _summarize(rows: Sequence[Mapping[str, Any]]) -> tuple[int, int, int, int]:
    scored = [row for row in rows if row["status"] == "scored"]
    return (
        sum(row["tp"] for row in scored),
        sum(row["fp"] for row in scored),
        sum(row["fn"] for row in scored),
        len(scored),
    )


def _assessments(value: object) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not value:
        raise EvidenceError("invalid_schema")
    identities: set[tuple[str, str, str, str]] = set()
    rows: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or any(
            not isinstance(item.get(field), str) or not item[field]
            for field in ("case_id", "engine", "rule_id", "file_path")
        ):
            raise EvidenceError("invalid_schema")
        if (
            not {"expected_trace", "trace_status", "observed_trace"} <= item.keys()
            or (item["expected_trace"] is not None and not isinstance(item["expected_trace"], dict))
            or item["trace_status"] not in (None, "verified", "missing", "mismatched")
            or not isinstance(item["observed_trace"], list)
        ):
            raise EvidenceError("invalid_schema")
        if item.get("status") not in ("scored", "unscored") or not all(
            _nonnegative_int(item.get(field)) for field in ("tp", "fp", "fn")
        ):
            raise EvidenceError("invalid_schema")
        if item["status"] == "scored":
            if item.get("reason") is not None:
                raise EvidenceError("invalid_schema")
        elif (
            not isinstance(item.get("reason"), str)
            or not item["reason"]
            or item["tp"]
            or item["fp"]
            or item["fn"]
        ):
            raise EvidenceError("invalid_schema")
        identity = (item["case_id"], item["engine"], item["rule_id"], item["file_path"])
        if identity in identities:
            raise EvidenceError("invalid_schema")
        identities.add(identity)
        rows.append(item)
    return rows


def _summary_map(value: object) -> dict[str, tuple[int, int, int, int]]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise EvidenceError("invalid_schema")
    return {key: _metric_counts(metrics) for key, metrics in value.items()}


def _expected_compose(manifest: LabeledCorpus) -> dict[tuple[str, str, str, str], int]:
    expected: dict[tuple[str, str, str, str], int] = {}
    positive_rules: set[str] = set()
    compose_cases = [
        case
        for case in manifest.cases
        if any(truth.engine == _ENGINE for truth in case.assessments)
    ]
    if (
        len(compose_cases) != _EXPECTED_COMPOSE_CASES
        or sum(case.case_id == "compose-benign" for case in compose_cases) != 1
    ):
        raise EvidenceError("invalid_cases")
    for case in compose_cases:
        truths = [truth for truth in case.assessments if truth.engine == _ENGINE]
        if (
            len(case.files) != 1
            or len(truths) != len(_RULES)
            or {truth.rule_id for truth in truths} != _RULES
            or any(truth.file_path != case.files[0][0] for truth in truths)
        ):
            raise EvidenceError("invalid_cases")
        positives = [truth for truth in truths if truth.expected_lines]
        if len(positives) != (0 if case.case_id == "compose-benign" else 1):
            raise EvidenceError("invalid_cases")
        positive_rules.update(truth.rule_id for truth in positives)
        for truth in truths:
            expected[(case.case_id, truth.engine, truth.rule_id, truth.file_path)] = len(
                truth.expected_lines
            )
    if positive_rules != _RULES:
        raise EvidenceError("invalid_cases")
    return expected


def _check_compose_coverage(
    payload: Mapping[str, Any], *, case_count: int, compose_case_count: int
) -> None:
    engine_coverage = payload["engine_coverage"]
    record = engine_coverage.get(_ENGINE)
    expected = {
        "runs": case_count,
        "completed": compose_case_count,
        "partial": 0,
        "not_run": 0,
        "error": 0,
        "skipped": case_count - compose_case_count,
        "eligible_files": compose_case_count,
        "scanned_files": compose_case_count,
    }
    if (
        not isinstance(record, dict)
        or any(not _nonnegative_int(record.get(field)) for field in (*expected, "elapsed_ms"))
        or any(record[field] != value for field, value in expected.items())
        or not _nonnegative_int(payload["engine_elapsed_ms"].get(_ENGINE))
        or payload["engine_elapsed_ms"][_ENGINE] != record["elapsed_ms"]
    ):
        raise EvidenceError("invalid_compose_coverage")


def check_evidence(payload: object, manifest: LabeledCorpus) -> tuple[int, int]:
    """Return Compose assessment and TP counts, or raise a stable failure code."""
    if not isinstance(payload, dict) or payload.get("scope") != "synthetic_regression":
        raise EvidenceError("invalid_schema")
    corpus = payload.get("corpus")
    coverage = payload.get("coverage")
    if (
        not isinstance(corpus, dict)
        or not isinstance(corpus.get("name"), str)
        or not corpus["name"]
        or not isinstance(corpus.get("manifest_sha256"), str)
        or not _SHA256.fullmatch(corpus["manifest_sha256"])
        or not isinstance(coverage, dict)
        or not all(
            _nonnegative_int(coverage.get(field))
            for field in (
                "cases_total",
                "cases_scanned",
                "assessments_total",
                "assessments_scored",
                "assessments_unscored",
            )
        )
        or not _nonnegative_int(payload.get("wall_elapsed_ms"))
        or not isinstance(payload.get("engine_elapsed_ms"), dict)
        or not isinstance(payload.get("engine_coverage"), dict)
    ):
        raise EvidenceError("invalid_schema")
    if corpus["manifest_sha256"] != manifest.manifest_sha256 or corpus["name"] != manifest.name:
        raise EvidenceError("manifest_mismatch")
    expected_compose = _expected_compose(manifest)
    rows = _assessments(payload.get("assessments"))
    by_rule = _summary_map(payload.get("by_rule"))
    by_engine = _summary_map(payload.get("by_engine"))
    global_metrics = _metric_counts(payload.get("metrics"))
    if (
        coverage["cases_scanned"] > coverage["cases_total"]
        or coverage["assessments_total"] != len(rows)
        or coverage["assessments_scored"] != sum(row["status"] == "scored" for row in rows)
        or coverage["assessments_unscored"] != sum(row["status"] == "unscored" for row in rows)
    ):
        raise EvidenceError("invalid_schema")
    if coverage["cases_total"] != len(manifest.cases) or coverage["cases_scanned"] != len(
        manifest.cases
    ):
        raise EvidenceError("invalid_case_coverage")
    if not _nonnegative_int(coverage.get("unassessed_finding_count")):
        raise EvidenceError("invalid_schema")
    if coverage["unassessed_finding_count"]:
        raise EvidenceError("unassessed_findings")
    _check_compose_coverage(
        payload,
        case_count=len(manifest.cases),
        compose_case_count=_EXPECTED_COMPOSE_CASES,
    )

    compose = [row for row in rows if row["engine"] == _ENGINE]
    assessed_rules = {row["rule_id"] for row in compose}
    summarized_rules = {
        key.removeprefix(f"{_ENGINE}:") for key in by_rule if key.startswith(f"{_ENGINE}:")
    }
    missing = (_RULES - assessed_rules) | (_RULES - summarized_rules)
    if missing:
        raise EvidenceError(f"missing_rules: {', '.join(sorted(missing))}")
    if (assessed_rules | summarized_rules) - _RULES:
        raise EvidenceError("unexpected_rules")

    rule_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    engine_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        rule_rows[f"{row['engine']}:{row['rule_id']}"].append(row)
        engine_rows[row["engine"]].append(row)
    if (
        set(by_rule) != set(rule_rows)
        or set(by_engine) != set(engine_rows)
        or any(by_rule[key] != _summarize(items) for key, items in rule_rows.items())
        or any(by_engine[key] != _summarize(items) for key, items in engine_rows.items())
        or global_metrics != _summarize(rows)
    ):
        raise EvidenceError("invalid_schema")

    unscored = sum(row["status"] == "unscored" for row in compose)
    if unscored:
        raise EvidenceError(f"unscored_assessments: {unscored}")
    no_positive = {
        rule
        for rule in _RULES
        if not any(row["rule_id"] == rule and row["tp"] + row["fn"] > 0 for row in compose)
    }
    if no_positive:
        raise EvidenceError(f"missing_positive_coverage: {', '.join(sorted(no_positive))}")
    tp, fp, fn, _ = _summarize(compose)
    if fp or fn:
        raise EvidenceError(f"compose_mismatch: fp={fp} fn={fn}")
    no_negative = {
        rule
        for rule in _RULES
        if not any(
            row["rule_id"] == rule and row["tp"] == row["fp"] == row["fn"] == 0 for row in compose
        )
    }
    if no_negative:
        raise EvidenceError(f"missing_negative_coverage: {', '.join(sorted(no_negative))}")
    observed_compose = {
        (row["case_id"], row["engine"], row["rule_id"], row["file_path"]): row for row in compose
    }
    if set(observed_compose) != set(expected_compose):
        missing_count = len(set(expected_compose) - set(observed_compose))
        extra_count = len(set(observed_compose) - set(expected_compose))
        raise EvidenceError(
            f"assessment_layout_mismatch: missing={missing_count} extra={extra_count}"
        )
    if any(
        row["tp"] + row["fn"] != expected_compose[identity]
        for identity, row in observed_compose.items()
    ):
        raise EvidenceError("expected_line_count")
    return len(compose), tp


def _load(path: Path) -> object:
    try:
        with path.open("rb") as stream:
            body = stream.read(_MAX_EVIDENCE_BYTES + 1)
    except OSError as error:
        raise EvidenceError("unreadable_evidence") from error
    if len(body) > _MAX_EVIDENCE_BYTES:
        raise EvidenceError("evidence_too_large")
    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid_json") from error


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("invalid_json")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise EvidenceError("invalid_json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence", required=True, type=Path, help="multi-engine benchmark JSON result"
    )
    parser.add_argument(
        "--cases", type=Path, default=_DEFAULT_CASES, help="labeled corpus manifest"
    )
    args = parser.parse_args(argv)
    try:
        try:
            manifest = load_labeled_corpus(args.cases)
        except EvaluationInputError as error:
            raise EvidenceError("invalid_cases") from error
        count, tp = check_evidence(_load(args.evidence), manifest)
    except EvidenceError as error:
        print(f"compose_evidence_error: {error}", file=sys.stderr)
        return 1
    print(f"compose_evidence_ok rules={len(_RULES)} assessments={count} tp={tp} fp=0 fn=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
