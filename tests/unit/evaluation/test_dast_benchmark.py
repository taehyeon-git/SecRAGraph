"""A labelled DAST result is scored only when its execution is proven complete."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from security_review.evaluation.dast_benchmark import (
    DastBenchmarkInputError,
    evaluate_dast_benchmark,
    load_manifest,
    render_benchmark_json,
    render_benchmark_markdown,
)


def _cases() -> list[dict[str, object]]:
    return [
        {
            "id": f"{rule}-{label}",
            "mode": mode,
            "method": "GET",
            "path": f"/{rule}-{label}",
            "rule_id": rule_id,
            "cwe_id": cwe,
            "expected": label == "vulnerable",
            "proof": "attack_probe" if mode == "active" else "route_request",
        }
        for rule, rule_id, cwe, mode in (
            ("sql", "ZAP/40018", "CWE-89", "active"),
            ("redirect", "ZAP/20019", "CWE-601", "active"),
            ("header", "ZAP/10021", "CWE-693", "passive"),
        )
        for label in ("vulnerable", "safe")
    ]


def _manifest(tmp_path: Path, cases: list[dict[str, object]] | None = None) -> Any:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "local-test-corpus",
                "provenance": "author-written-synthetic",
                "cases": _cases() if cases is None else cases,
            }
        ),
        encoding="utf-8",
    )
    return load_manifest(path)


def _report(mode: str, findings: tuple[Any, ...] = (), *, completed: bool = True) -> Any:
    paths = [case["path"] for case in _cases() if case["mode"] == mode]
    execution = SimpleNamespace(
        engine="zap",
        kind="dast",
        status="completed" if completed else "partial",
        checks=(f"openapi-{mode}",),
        eligible_endpoints=tuple(f"GET {path}" for path in paths),
        elapsed_ms=123 if mode == "passive" else 456,
        version="ghcr.io/zaproxy/zaproxy:stable@sha256:" + "a" * 64,
    )
    return SimpleNamespace(findings=findings, executions=(execution,))


def _finding(rule_id: str, path: str, method: str = "GET", cwe_ids: tuple[str, ...] = ()) -> Any:
    return SimpleNamespace(
        engine="zap", rule_id=rule_id, http_method=method, http_path=path, cwe_ids=cwe_ids
    )


def _stats(*, passive: bool = False, active: bool = False) -> dict[str, object]:
    routes = {str(case["path"]): int(passive) for case in _cases()}
    probes = {str(case["path"]): int(active) for case in _cases()}
    return {"route_requests": routes, "attack_probes": probes}


def _evaluate(manifest: Any, passive: Any, active: Any, **kwargs: object) -> Any:
    return evaluate_dast_benchmark(
        manifest,
        passive,
        active,
        _stats(),
        _stats(passive=True),
        _stats(passive=True, active=True),
        fixture_image_id="sha256:" + "b" * 64,
        source_revision="c" * 40,
        total_elapsed_ms=987,
        **kwargs,
    )


def test_exact_labels_score_tp_fp_fn_tn_and_exclude_other_alerts(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    passive = _report(
        "passive",
        (_finding("ZAP/10021", "/header-vulnerable"), _finding("ZAP/10024", "/header-safe")),
    )
    active = _report(
        "active",
        (
            _finding("ZAP/40018", "/sql-vulnerable", cwe_ids=("CWE-89",)),
            _finding("ZAP/20019", "/redirect-safe"),
            _finding("ZAP/40018", "/sql-vulnerable", "POST"),
        ),
    )
    result = _evaluate(manifest, passive, active).to_dict()
    assert result["metrics"]["tp"] == 2
    assert result["metrics"]["fp"] == 1
    assert result["metrics"]["fn"] == 1
    assert result["metrics"]["tn"] == 2
    assert result["metrics"]["precision"] == pytest.approx(2 / 3)
    assert result["metrics"]["recall"] == pytest.approx(2 / 3)
    assert result["unassessed_findings"] == 2
    assert result["rules"]["ZAP/20019"]["fp"] == 1
    assert result["cwe_mismatch_cases"] == 2
    outcomes = {case["id"]: case for case in result["cases"]}
    assert outcomes["sql-vulnerable"]["cwe_match"] is True
    assert outcomes["redirect-safe"]["cwe_match"] is False
    assert outcomes["sql-safe"]["cwe_match"] is None
    assert result["timing"]["passive_elapsed_ms"] == 123
    assert result["timing"]["active_elapsed_ms"] == 456
    assert result["timing"]["total_elapsed_ms"] == 987
    assert result["manifest_sha256"] == manifest.sha256


@pytest.mark.parametrize(
    "change", ["duplicate", "unbalanced", "wrong_proof", "wrong_method", "bad_path"]
)
def test_rejects_malformed_manifest(tmp_path: Path, change: str) -> None:
    cases = _cases()
    if change == "duplicate":
        cases.append(dict(cases[0], id="duplicate-id"))
    elif change == "unbalanced":
        cases.pop(1)
    elif change == "wrong_proof":
        cases[0]["proof"] = "route_request"
    elif change == "wrong_method":
        cases[0]["method"] = "POST"
    else:
        cases[0]["path"] = "//outside"
    with pytest.raises(DastBenchmarkInputError):
        _manifest(tmp_path, cases)


def test_missing_probe_and_incomplete_report_are_unscored_failures(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    with pytest.raises(DastBenchmarkInputError, match="incomplete"):
        _evaluate(manifest, _report("passive"), _report("active", completed=False))
    after_active = _stats(passive=True, active=True)
    after_active["attack_probes"]["/sql-safe"] = 0  # type: ignore[index]
    with pytest.raises(DastBenchmarkInputError, match="proof"):
        evaluate_dast_benchmark(
            manifest,
            _report("passive"),
            _report("active"),
            _stats(),
            _stats(passive=True),
            after_active,
            fixture_image_id="sha256:" + "b" * 64,
            source_revision="c" * 40,
            total_elapsed_ms=987,
        )


def test_missing_seed_and_passive_visit_are_unscored_failures(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    active = _report("active")
    active.executions[0].eligible_endpoints = ("GET /sql-vulnerable",)
    with pytest.raises(DastBenchmarkInputError, match="seed"):
        _evaluate(manifest, _report("passive"), active)
    after_passive = _stats(passive=True)
    after_passive["route_requests"]["/header-safe"] = 0  # type: ignore[index]
    with pytest.raises(DastBenchmarkInputError, match="proof"):
        evaluate_dast_benchmark(
            manifest,
            _report("passive"),
            _report("active"),
            _stats(),
            after_passive,
            _stats(passive=True, active=True),
            fixture_image_id="sha256:" + "b" * 64,
            source_revision="c" * 40,
            total_elapsed_ms=987,
        )


def test_unpinned_zap_or_missing_manifest_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(DastBenchmarkInputError, match="manifest_unavailable"):
        load_manifest(tmp_path / "missing.json")
    manifest = _manifest(tmp_path)
    active = _report("active")
    active.executions[0].version = "ghcr.io/zaproxy/zaproxy:stable"
    with pytest.raises(DastBenchmarkInputError, match="inconsistent_zap_version"):
        _evaluate(manifest, _report("passive"), active)


def test_zero_denominators_and_rendering_exclude_payloads(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    result = _evaluate(manifest, _report("passive"), _report("active"))
    evidence = json.loads(render_benchmark_json(result))
    assert evidence["metrics"]["precision"] is None
    assert evidence["metrics"]["recall"] == 0.0
    assert evidence["metrics"]["f1"] == 0.0
    assert evidence["coverage"]["cases_scored"] == 6
    markdown = render_benchmark_markdown(result)
    assert "ZAP/40018" in markdown
    assert "author-written" in markdown
    for rendered in (markdown, render_benchmark_json(result)):
        assert "Session " not in rendered
        assert "?next=" not in rendered
        assert "?username=" not in rendered
