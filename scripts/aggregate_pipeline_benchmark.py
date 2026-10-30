"""Fail-closed, same-run summary of the distinct SecRAGraph CI evidence tracks."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_MAX_FILE_BYTES = 20_000_000
_MAX_FILES = 40
_SOURCE_FILES = {
    "api": ("pipeline-api.json", "pipeline-api.md"),
    "scanner": (
        "multiengine-scanner.json",
        "multiengine-scanner.md",
        "rag.json",
        "rag.md",
        "pipeline-contract.json",
        "pipeline-contract.md",
    ),
    "dast": (
        "dast.json",
        "dast.md",
        "dast.sarif",
        "dast-active.json",
        "dast-active.md",
        "dast-active.sarif",
        "dast-benchmark.json",
        "dast-benchmark.md",
    ),
    "container": (
        "container.manifest.json",
        "container.json",
        "container.md",
        "container.sarif",
        "container.cdx.json",
    ),
    "history": ("history.json", "history.md", "history.sarif"),
}
_API_CHECKS = frozenset(
    {
        "api_ready",
        "web_ready",
        "member_login",
        "expected_findings",
        "engine_coverage",
        "persisted_json",
        "markdown",
        "sarif",
        "member_isolation",
        "redaction",
    }
)
_API_STAGES = frozenset(
    {
        "startup",
        "api_ready",
        "web_ready",
        "member_setup",
        "login",
        "upload",
        "persisted_json",
        "markdown",
        "sarif",
        "cleanup",
    }
)
_API_ENGINES = frozenset({"opengrep", "gitleaks", "checkov", "compose-policy"})


class PipelineEvidenceError(ValueError):
    """The bundle must not publish incomplete, stale or malformed evidence."""


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PipelineEvidenceError("invalid_evidence_object")
    return value


def _integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PipelineEvidenceError("invalid_evidence_count")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise PipelineEvidenceError("invalid_evidence_digest")
    return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise PipelineEvidenceError("duplicate_evidence_key")
        record[key] = value
    return record


def _read(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PipelineEvidenceError("evidence_file_missing")
    try:
        size = path.stat().st_size
        if not 0 < size <= _MAX_FILE_BYTES:
            raise PipelineEvidenceError("evidence_file_size_invalid")
        return _object(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs))
    except (OSError, UnicodeError, ValueError) as error:
        raise PipelineEvidenceError("evidence_file_invalid") from error


def _revision(value: object, expected: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise PipelineEvidenceError("evidence_revision_mismatch")


def _metrics(value: object, keys: tuple[str, ...]) -> dict[str, Any]:
    result = _object(value)
    for key in keys:
        _integer(result.get(key))
    return result


def _rate_matches(actual: object, expected: float | None) -> bool:
    if expected is None:
        return actual is None
    return type(actual) in (int, float) and actual == expected


def _validate_derived_rates(metrics: dict[str, Any]) -> None:
    tp, fp, fn = (metrics[key] for key in ("tp", "fp", "fn"))
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    f1_denominator = 2 * tp + fp + fn
    if (
        _integer(metrics.get("precision_denominator")) != precision_denominator
        or _integer(metrics.get("recall_denominator")) != recall_denominator
        or not _rate_matches(
            metrics.get("precision"), tp / precision_denominator if precision_denominator else None
        )
        or not _rate_matches(
            metrics.get("recall"), tp / recall_denominator if recall_denominator else None
        )
        or not _rate_matches(metrics.get("f1"), 2 * tp / f1_denominator if f1_denominator else None)
    ):
        raise PipelineEvidenceError("derived_metric_inconsistent")


def _api(data: dict[str, Any], revision: str) -> dict[str, object]:
    if data.get("schema_version") != 1 or data.get("status") != "completed":
        raise PipelineEvidenceError("api_benchmark_incomplete")
    _revision(data.get("source_revision"), revision)
    if data.get("source_dirty") is not False:
        raise PipelineEvidenceError("api_source_dirty")
    fixture_sha = _digest(data.get("fixture_sha256"))
    stages = _object(data.get("stages_ms"))
    if set(stages) != _API_STAGES:
        raise PipelineEvidenceError("api_stages_incomplete")
    for duration in stages.values():
        _integer(duration)
    checks = _object(data.get("checks"))
    if set(checks) != _API_CHECKS or any(value is not True for value in checks.values()):
        raise PipelineEvidenceError("api_checks_incomplete")
    executions = data.get("executions")
    if not isinstance(executions, list):
        raise PipelineEvidenceError("api_execution_invalid")
    by_engine: dict[str, dict[str, object]] = {}
    for raw in executions:
        item = _object(raw)
        engine = item.get("engine")
        if not isinstance(engine, str) or engine in by_engine or engine not in _API_ENGINES:
            raise PipelineEvidenceError("api_engine_identity_invalid")
        if item.get("status") != "completed":
            raise PipelineEvidenceError("api_engine_incomplete")
        semantics = "finding_paths_only" if engine == "gitleaks" else "tool_confirmed_scanned_files"
        if item.get("reported_path_semantics") != semantics:
            raise PipelineEvidenceError("api_engine_coverage_invalid")
        elapsed = _integer(item.get("elapsed_ms"))
        eligible, scanned = item.get("eligible_files"), item.get("scanned_files")
        if (
            not isinstance(eligible, list)
            or not isinstance(scanned, list)
            or not all(isinstance(path, str) for path in (*eligible, *scanned))
        ):
            raise PipelineEvidenceError("api_engine_coverage_invalid")
        if len(eligible) < len(scanned) or not set(scanned) <= set(eligible):
            raise PipelineEvidenceError("api_engine_coverage_invalid")
        by_engine[engine] = {
            "status": item["status"],
            "elapsed_ms": elapsed,
            "eligible_files": len(eligible),
            "scanned_files": len(scanned),
            "reported_path_semantics": semantics,
        }
    if set(by_engine) != _API_ENGINES:
        raise PipelineEvidenceError("api_engine_missing")
    report = _object(data.get("report"))
    if report.get("scan_status") != "completed":
        raise PipelineEvidenceError("api_report_incomplete")
    findings = _integer(report.get("finding_count"))
    warnings = _integer(report.get("warnings_count"))
    if findings < len(_API_ENGINES) or warnings != 0:
        raise PipelineEvidenceError("api_report_incomplete")
    return {
        "source_revision_status": "verified",
        "fixture_sha256": fixture_sha,
        "stages_ms": stages,
        "checks_passed": len(checks),
        "checks_total": len(checks),
        "executions": by_engine,
        "report": {"status": report["scan_status"], "findings": findings, "warnings": warnings},
        "interpretation": (
            "Authenticated synthetic ZIP and persisted report contract; not field accuracy."
        ),
    }


def _scanner(data: dict[str, Any]) -> dict[str, object]:
    if data.get("scope") != "synthetic_regression":
        raise PipelineEvidenceError("scanner_scope_invalid")
    corpus = _object(data.get("corpus"))
    manifest_sha = _digest(corpus.get("manifest_sha256"))
    coverage = _object(data.get("coverage"))
    total = _integer(coverage.get("cases_total"), minimum=1)
    if _integer(coverage.get("cases_scanned")) != total:
        raise PipelineEvidenceError("scanner_cases_incomplete")
    assessments = _integer(coverage.get("assessments_total"), minimum=1)
    if (
        _integer(coverage.get("assessments_scored")) != assessments
        or _integer(coverage.get("assessments_unscored")) != 0
    ):
        raise PipelineEvidenceError("scanner_assessments_incomplete")
    metrics = _metrics(data.get("metrics"), ("tp", "fp", "fn"))
    _validate_derived_rates(metrics)
    elapsed = _integer(data.get("wall_elapsed_ms"))
    return {
        "source_revision_status": "unverified",
        "manifest_sha256": manifest_sha,
        "cases_scanned": total,
        "assessments_scored": assessments,
        "metrics": {
            key: metrics.get(key) for key in ("tp", "fp", "fn", "precision", "recall", "f1")
        },
        "wall_elapsed_ms": elapsed,
        "interpretation": (
            "Author-written scanner regression labels; no real-world detection estimate."
        ),
    }


def _rag(data: dict[str, Any], revision: str) -> dict[str, object]:
    _revision(data.get("git_revision"), revision)
    if data.get("git_dirty") is not False or data.get("passed") is not True:
        raise PipelineEvidenceError("rag_evaluation_incomplete")
    cases = data.get("cases")
    if (
        not isinstance(cases, list)
        or not cases
        or any(not isinstance(case, dict) or case.get("passed") is not True for case in cases)
    ):
        raise PipelineEvidenceError("rag_cases_incomplete")
    manifest_sha = _digest(data.get("manifest_sha256"))
    corpus_sha = _digest(data.get("corpus_sha256"))
    _digest(data.get("source_fingerprint"))
    raw_metrics = _object(data.get("metrics"))
    metrics: dict[str, object] = {}
    for name, raw in raw_metrics.items():
        metric = _object(raw)
        numerator = _integer(metric.get("numerator"))
        denominator = _integer(metric.get("denominator"))
        not_applicable = _integer(metric.get("not_applicable"))
        if numerator > denominator or denominator + not_applicable != len(cases):
            raise PipelineEvidenceError("rag_denominator_invalid")
        if not _rate_matches(metric.get("value"), numerator / denominator if denominator else None):
            raise PipelineEvidenceError("rag_value_inconsistent")
        metrics[name] = {
            "numerator": numerator,
            "denominator": denominator,
            "not_applicable": not_applicable,
            "value": metric.get("value"),
        }
    if not metrics:
        raise PipelineEvidenceError("rag_metrics_missing")
    return {
        "source_revision_status": "verified",
        "manifest_sha256": manifest_sha,
        "corpus_sha256": corpus_sha,
        "cases_passed": len(cases),
        "cases_total": len(cases),
        "metrics": metrics,
        "interpretation": (
            "Deterministic local RAG graph contract; live model answer quality unmeasured."
        ),
    }


def _dast(data: dict[str, Any], revision: str) -> dict[str, object]:
    if data.get("schema_version") != 1 or data.get("scope") != "author_written_regression":
        raise PipelineEvidenceError("dast_scope_invalid")
    _revision(data.get("source_revision"), revision)
    if data.get("source_dirty") is not False:
        raise PipelineEvidenceError("dast_source_dirty")
    manifest_sha = _digest(data.get("manifest_sha256"))
    if data.get("execution_status") != {"passive": "completed", "active": "completed"}:
        raise PipelineEvidenceError("dast_execution_incomplete")
    coverage = _object(data.get("coverage"))
    total = _integer(coverage.get("cases_total"), minimum=1)
    if _integer(coverage.get("cases_scored")) != total:
        raise PipelineEvidenceError("dast_cases_incomplete")
    metrics = _metrics(data.get("metrics"), ("tp", "fp", "fn", "tn", "cases_scored"))
    _validate_derived_rates(metrics)
    if (
        metrics["cases_scored"] != total
        or sum(metrics[key] for key in ("tp", "fp", "fn", "tn")) != total
    ):
        raise PipelineEvidenceError("dast_metrics_inconsistent")
    elapsed = _integer(_object(data.get("timing")).get("total_elapsed_ms"))
    return {
        "source_revision_status": "verified",
        "manifest_sha256": manifest_sha,
        "cases_scored": total,
        "metrics": {
            key: metrics.get(key) for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1")
        },
        "wall_elapsed_ms": elapsed,
        "interpretation": "Disposable author-written HTTP fixture; no production DAST estimate.",
    }


def _provider_contract(data: dict[str, Any], revision: str) -> dict[str, object]:
    if (
        data.get("schema_version") != 1
        or data.get("scope") != "synthetic_adapter_contract"
        or data.get("passed") is not True
        or data.get("source_dirty") is not False
    ):
        raise PipelineEvidenceError("provider_contract_incomplete")
    _revision(data.get("source_revision"), revision)
    coverage = _object(data.get("coverage"))
    total = _integer(coverage.get("cases_total"), minimum=1)
    if _integer(coverage.get("cases_passed")) != total:
        raise PipelineEvidenceError("provider_contract_cases_incomplete")
    providers = _object(data.get("providers"))
    if set(providers) != {"dependency_audit", "cwe", "rag"}:
        raise PipelineEvidenceError("provider_contract_missing")
    calls: dict[str, int] = {}
    for name in providers:
        calls[name] = _integer(_object(providers[name]).get("calls"), minimum=1)
    dependency = _object(providers["dependency_audit"])
    coordinates = dependency.get("coordinates")
    if (
        not isinstance(coordinates, list)
        or not coordinates
        or not all(
            isinstance(coordinate, str) and coordinate.startswith("PyPI:")
            for coordinate in coordinates
        )
    ):
        raise PipelineEvidenceError("provider_contract_osv_incomplete")
    cwe = _object(providers["cwe"])
    if not isinstance(cwe.get("requested_ids"), list) or not cwe["requested_ids"]:
        raise PipelineEvidenceError("provider_contract_cwe_incomplete")
    rag = _object(providers["rag"])
    if rag.get("osv_finding_cited") is not True:
        raise PipelineEvidenceError("provider_contract_osv_rag_missing")
    report = _object(data.get("report"))
    if (
        report.get("status") != "completed"
        or report.get("persisted") is not True
        or _integer(report.get("finding_count"), minimum=2) < 2
    ):
        raise PipelineEvidenceError("provider_contract_report_incomplete")
    executions = _object(report.get("executions"))
    if set(executions) != {"fixture_sast", "osv"} or any(
        _object(execution).get("status") != "completed" for execution in executions.values()
    ):
        raise PipelineEvidenceError("provider_contract_execution_incomplete")
    references = _object(report.get("reference_ids_by_engine"))
    osv_references = references.get("osv")
    if (
        not isinstance(osv_references, list)
        or len(osv_references) < 2
        or not any(isinstance(ref, str) and ref.startswith("osv:") for ref in osv_references)
        or not any(isinstance(ref, str) and ref.startswith("fixture:") for ref in osv_references)
    ):
        raise PipelineEvidenceError("provider_contract_osv_rag_missing")
    retrieval_calls = _object(data.get("retrieval_calls"))
    identical = _integer(retrieval_calls.get("identical_findings"), minimum=2)
    observed = _integer(retrieval_calls.get("observed_calls"), minimum=1)
    if observed != 1 or retrieval_calls.get("all_cited") is not True:
        raise PipelineEvidenceError("provider_contract_cache_invalid")
    return {
        "source_revision_status": "verified",
        "fixture_sha256": _digest(data.get("fixture_sha256")),
        "cases_passed": total,
        "providers": {
            name: {
                "calls": calls[name],
                **({"osv_finding_cited": True} if name == "rag" else {}),
            }
            for name in sorted(providers)
        },
        "retrieval_calls": {"identical_findings": identical, "observed_calls": observed},
        "finding_count": report["finding_count"],
        "elapsed_ms": _integer(data.get("elapsed_ms")),
        "interpretation": (
            "Injected OSV/CWE/RAG graph-edge contract; live provider quality unmeasured."
        ),
    }


def _container(data: dict[str, Any], root: Path) -> dict[str, object]:
    if data.get("schema_version") != 1 or data.get("execution_status") != "completed":
        raise PipelineEvidenceError("image_scan_incomplete")
    image_id = data.get("image_id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise PipelineEvidenceError("image_id_invalid")
    sbom_sha = _digest(data.get("sbom_sha256"))
    artifacts = _object(data.get("artifacts"))
    if set(artifacts) != {
        "container.json",
        "container.md",
        "container.sarif",
        "container.cdx.json",
    }:
        raise PipelineEvidenceError("image_artifact_set_invalid")
    for name, expected in artifacts.items():
        if name not in {"container.json", "container.md", "container.sarif", "container.cdx.json"}:
            raise PipelineEvidenceError("image_artifact_invalid")
        path = root / "container" / name
        if (
            path.is_symlink()
            or not path.is_file()
            or not 0 < path.stat().st_size <= _MAX_FILE_BYTES
        ):
            raise PipelineEvidenceError("image_artifact_missing")
        if sha256(path.read_bytes()).hexdigest() != _digest(expected):
            raise PipelineEvidenceError("image_artifact_digest_mismatch")
    if artifacts.get("container.cdx.json") != sbom_sha:
        raise PipelineEvidenceError("sbom_digest_mismatch")
    return {
        "source_revision_status": "unverified",
        "image_id": image_id,
        "sbom_sha256": sbom_sha,
        "sbom_component_count": _integer(data.get("sbom_component_count"), minimum=1),
        "vulnerability_count": _integer(data.get("image_vulnerability_count")),
        "configuration_count": _integer(data.get("image_config_count")),
        "interpretation": "CI-built image and SBOM; advisory DB is time-varying.",
    }


def _history(data: dict[str, Any], revision: str) -> dict[str, object]:
    if (
        data.get("status") != "completed"
        or data.get("warnings") != []
        or data.get("findings") != []
    ):
        raise PipelineEvidenceError("history_gate_incomplete")
    executions = data.get("executions")
    if not isinstance(executions, list) or len(executions) != 1:
        raise PipelineEvidenceError("history_execution_invalid")
    execution = _object(executions[0])
    _revision(execution.get("revision_head"), revision)
    if execution.get("engine") != "gitleaks-history" or execution.get("status") != "completed":
        raise PipelineEvidenceError("history_execution_incomplete")
    return {
        "source_revision_status": "verified",
        "selected_commit_count": _integer(execution.get("selected_commit_count"), minimum=1),
        "elapsed_ms": _integer(execution.get("elapsed_ms")),
        "finding_count": 0,
        "interpretation": "Selected trusted Git history gate; not member-upload coverage.",
    }


def _artifact_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    count = 0
    for component in _SOURCE_FILES:
        directory = root / component
        if directory.is_symlink() or not directory.is_dir():
            raise PipelineEvidenceError("evidence_component_missing")
        for path in directory.rglob("*"):
            if path.is_symlink() or not path.is_file() or path.parent != directory:
                raise PipelineEvidenceError("evidence_artifact_unsafe")
            size = path.stat().st_size
            if not 0 < size <= _MAX_FILE_BYTES:
                raise PipelineEvidenceError("evidence_artifact_size_invalid")
            hashes[f"{component}/{path.name}"] = sha256(path.read_bytes()).hexdigest()
            count += 1
            if count > _MAX_FILES:
                raise PipelineEvidenceError("evidence_artifact_count_invalid")
    for component, names in _SOURCE_FILES.items():
        if any(f"{component}/{name}" not in hashes for name in names):
            raise PipelineEvidenceError("evidence_artifact_missing")
    return dict(sorted(hashes.items()))


def aggregate(
    root: Path,
    *,
    run_id: str,
    source_revision: str,
    dependency_status: str,
    runner_os: str,
    runner_arch: str,
) -> dict[str, object]:
    """Validate same-run inputs and return a bounded, source-free summary."""

    if not _RUN_ID.fullmatch(run_id) or not _SHA.fullmatch(source_revision):
        raise PipelineEvidenceError("workflow_identity_invalid")
    if dependency_status != "success":
        raise PipelineEvidenceError("dependency_audit_incomplete")
    if runner_os not in {"Linux", "Windows", "macOS"} or runner_arch not in {"X64", "ARM64"}:
        raise PipelineEvidenceError("runner_identity_invalid")
    hashes = _artifact_hashes(root)
    api = _api(_read(root / "api/pipeline-api.json"), source_revision)
    scanner = _scanner(_read(root / "scanner/multiengine-scanner.json"))
    rag = _rag(_read(root / "scanner/rag.json"), source_revision)
    provider_contract = _provider_contract(
        _read(root / "scanner/pipeline-contract.json"), source_revision
    )
    dast = _dast(_read(root / "dast/dast-benchmark.json"), source_revision)
    container = _container(_read(root / "container/container.manifest.json"), root)
    history = _history(_read(root / "history/history.json"), source_revision)
    return {
        "schema_version": 1,
        "status": "completed",
        "run_id": run_id,
        "source_revision": source_revision,
        "runner": {"os": runner_os, "arch": runner_arch},
        "artifact_sha256": hashes,
        "tracks": {
            "api": api,
            "scanner": scanner,
            "rag": rag,
            "provider_contract": provider_contract,
            "dast": dast,
            "container": container,
            "git_history": history,
            "dependency_audit": {
                "status": "success",
                "measurement": "status_only",
                "interpretation": (
                    "Upstream pip-audit gate passed; no vulnerability count artifact."
                ),
            },
        },
        "interpretation": (
            "One CI run links distinct operational and authored regression tracks. "
            "No pooled accuracy score or real-world detection rate is implied."
        ),
    }


def render_markdown(result: Mapping[str, object]) -> str:
    """Summarize separate tracks without combining unlike denominators."""

    tracks = _object(result["tracks"])
    api = _object(tracks["api"])
    scanner = _object(tracks["scanner"])
    scanner_metrics = _object(scanner["metrics"])
    rag = _object(tracks["rag"])
    provider_contract = _object(tracks["provider_contract"])
    dast = _object(tracks["dast"])
    dast_metrics = _object(dast["metrics"])
    container = _object(tracks["container"])
    history = _object(tracks["git_history"])
    runner = _object(result["runner"])
    lines = [
        "# SecRAGraph whole-tool pipeline benchmark",
        "",
        f"- CI run: `{result['run_id']}`",
        f"- Source revision: `{result['source_revision']}`",
        f"- Runner: `{runner['os']}/{runner['arch']}`",
        (
            "- Result: completed; primary JSON contracts validated and companion "
            "files present with SHA-256 hashes"
        ),
        "",
        "| Track | Scope | Result |",
        "| --- | --- | --- |",
        (
            "| Authenticated API | Synthetic ZIP and persisted reports | "
            f"{api['checks_passed']}/{api['checks_total']} checks |"
        ),
        (
            "| SAST/secret/IaC scanner | Author-written labels | "
            f"{scanner['cases_scanned']} cases; TP {scanner_metrics['tp']}, "
            f"FP {scanner_metrics['fp']}, FN {scanner_metrics['fn']} |"
        ),
        (
            "| RAG graph | Deterministic local contract | "
            f"{rag['cases_passed']}/{rag['cases_total']} cases |"
        ),
        (
            "| OSV/CWE/RAG graph edges | Injected adapter contract | "
            f"{provider_contract['cases_passed']} case |"
        ),
        (
            "| DAST | Disposable authored API | "
            f"{dast['cases_scored']} cases; TP {dast_metrics['tp']}, "
            f"FP {dast_metrics['fp']}, FN {dast_metrics['fn']}, TN {dast_metrics['tn']} |"
        ),
        (
            "| Container/SBOM | CI-built image | "
            f"{container['sbom_component_count']} components; "
            f"{container['vulnerability_count']} vulnerability findings |"
        ),
        (
            "| Git history | Trusted selected commits | "
            f"{history['selected_commit_count']} commits; 0 new findings |"
        ),
        "| Dependency audit | Upstream pip-audit gate | success; status only |",
        "",
        (
            "Counts have separate denominators. Authored fixtures are regression checks, "
            "not real-world detection rates."
        ),
        (
            "External OSV/CWE and live LLM answer quality are not measured by the "
            "authenticated API fixture."
        ),
        (
            "Image and scanner artifacts without embedded source revisions are marked "
            "unverified in JSON; same-run artifact download supplies run linkage."
        ),
    ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("build/evidence"))
    args = parser.parse_args(argv)
    try:
        result = aggregate(
            args.evidence_root,
            run_id=os.environ.get("GITHUB_RUN_ID", ""),
            source_revision=os.environ.get("GITHUB_SHA", ""),
            dependency_status=os.environ.get("DEPENDENCY_SECURITY_RESULT", ""),
            runner_os=os.environ.get("RUNNER_OS", ""),
            runner_arch=os.environ.get("RUNNER_ARCH", ""),
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "pipeline-benchmark.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (args.output_dir / "pipeline-benchmark.md").write_text(
            render_markdown(result), encoding="utf-8"
        )
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"pipeline benchmark unavailable: {type(error).__name__}", file=sys.stderr)
        return 2
    print("Whole-tool pipeline benchmark validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
