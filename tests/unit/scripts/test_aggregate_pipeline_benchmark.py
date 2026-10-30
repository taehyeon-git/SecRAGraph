"""The whole-run bundle keeps component scopes and fails closed."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.aggregate_pipeline_benchmark import PipelineEvidenceError, aggregate

REVISION = "a" * 40


def _write(root: Path, component: str, name: str, payload: object) -> None:
    target = root / component / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload), encoding="utf-8")


def _fixture(root: Path) -> None:
    digest = "b" * 64
    _write(
        root,
        "api",
        "pipeline-api.json",
        {
            "schema_version": 1,
            "source_revision": REVISION,
            "source_dirty": False,
            "status": "completed",
            "fixture_sha256": digest,
            "stages_ms": {
                key: 1
                for key in (
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
                )
            },
            "checks": {
                key: True
                for key in (
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
                )
            },
            "executions": [
                {
                    "engine": engine,
                    "kind": kind,
                    "status": "completed",
                    "elapsed_ms": 2,
                    "reported_path_semantics": (
                        "finding_paths_only"
                        if engine == "gitleaks"
                        else "tool_confirmed_scanned_files"
                    ),
                    "eligible_files": ["app.py"],
                    "scanned_files": ["app.py"],
                    "checks": ["test"],
                }
                for engine, kind in (
                    ("opengrep", "sast"),
                    ("python-flow", "sast"),
                    ("gitleaks", "secret"),
                    ("checkov", "configuration"),
                    ("compose-policy", "configuration"),
                )
            ],
            "limitations": ["External provider quality unmeasured."],
            "report": {"scan_status": "completed", "finding_count": 4, "warnings_count": 0},
        },
    )
    _write(
        root,
        "scanner",
        "multiengine-scanner.json",
        {
            "scope": "synthetic_regression",
            "corpus": {"name": "authored", "manifest_sha256": digest, "source_revision": None},
            "coverage": {
                "cases_total": 3,
                "cases_scanned": 3,
                "assessments_total": 3,
                "assessments_scored": 3,
                "assessments_unscored": 0,
            },
            "metrics": {
                "tp": 1,
                "fp": 0,
                "fn": 1,
                "precision_denominator": 1,
                "recall_denominator": 2,
                "precision": 1.0,
                "recall": 0.5,
                "f1": 2 / 3,
            },
            "wall_elapsed_ms": 50,
        },
    )
    _write(
        root,
        "scanner",
        "rag.json",
        {
            "git_revision": REVISION,
            "git_dirty": False,
            "passed": True,
            "manifest_sha256": digest,
            "corpus_sha256": digest,
            "source_fingerprint": digest,
            "cases": [{"passed": True}, {"passed": True}],
            "metrics": {
                "path_match": {"numerator": 2, "denominator": 2, "not_applicable": 0, "value": 1.0}
            },
        },
    )
    _write(
        root,
        "scanner",
        "pipeline-contract.json",
        {
            "schema_version": 1,
            "scope": "synthetic_adapter_contract",
            "source_revision": REVISION,
            "source_dirty": False,
            "passed": True,
            "fixture_sha256": digest,
            "coverage": {"cases_passed": 1, "cases_total": 1},
            "providers": {
                "dependency_audit": {
                    "calls": 1,
                    "coordinates": ["PyPI:pipeline-fixture-pkg:1.0.0"],
                },
                "cwe": {"calls": 1, "requested_ids": ["CWE-95"]},
                "rag": {
                    "calls": 2,
                    "osv_finding_cited": True,
                },
            },
            "retrieval_calls": {"identical_findings": 20, "observed_calls": 1, "all_cited": True},
            "report": {
                "status": "completed",
                "finding_count": 2,
                "persisted": True,
                "executions": {
                    "fixture_sast": {"status": "completed"},
                    "osv": {"status": "completed"},
                },
                "reference_ids_by_engine": {
                    "fixture_sast": ["mitre:CWE-95", "fixture:guide:1"],
                    "osv": ["osv:OSV-TEST-0001", "fixture:guide:1"],
                },
            },
            "elapsed_ms": 12,
            "limitations": ["Synthetic adapters."],
        },
    )
    _write(
        root,
        "dast",
        "dast-benchmark.json",
        {
            "schema_version": 1,
            "scope": "author_written_regression",
            "source_revision": REVISION,
            "source_dirty": False,
            "manifest_sha256": digest,
            "execution_status": {"active": "completed", "passive": "completed"},
            "coverage": {"cases_total": 8, "cases_scored": 8},
            "metrics": {
                "tp": 3,
                "fp": 0,
                "fn": 1,
                "tn": 4,
                "cases_scored": 8,
                "precision_denominator": 3,
                "recall_denominator": 4,
                "precision": 1.0,
                "recall": 0.75,
                "f1": 6 / 7,
            },
            "timing": {"total_elapsed_ms": 500},
        },
    )
    _write(root, "container", "container.cdx.json", {"bomFormat": "CycloneDX"})
    sbom = root / "container" / "container.cdx.json"
    for name in ("container.json", "container.md", "container.sarif"):
        (root / "container" / name).write_text("fixture", encoding="utf-8")
    container_artifacts = {
        name: sha256((root / "container" / name).read_bytes()).hexdigest()
        for name in ("container.json", "container.md", "container.sarif", "container.cdx.json")
    }
    _write(
        root,
        "container",
        "container.manifest.json",
        {
            "schema_version": 1,
            "execution_status": "completed",
            "image_id": "sha256:" + digest,
            "sbom_sha256": sha256(sbom.read_bytes()).hexdigest(),
            "sbom_component_count": 4,
            "image_vulnerability_count": 1,
            "image_config_count": 0,
            "artifacts": container_artifacts,
        },
    )
    _write(
        root,
        "history",
        "history.json",
        {
            "status": "completed",
            "findings": [],
            "warnings": [],
            "executions": [
                {
                    "engine": "gitleaks-history",
                    "kind": "secret",
                    "status": "completed",
                    "revision_head": REVISION,
                    "selected_commit_count": 1,
                    "elapsed_ms": 4,
                }
            ],
        },
    )
    companion_files = {
        "api": ("pipeline-api.md",),
        "scanner": ("multiengine-scanner.md", "rag.md", "pipeline-contract.md"),
        "dast": (
            "dast.json",
            "dast.md",
            "dast.sarif",
            "dast-active.json",
            "dast-active.md",
            "dast-active.sarif",
            "dast-benchmark.md",
        ),
        "history": ("history.md", "history.sarif"),
    }
    for component, names in companion_files.items():
        for name in names:
            (root / component / name).write_text("fixture", encoding="utf-8")


def _aggregate(root: Path) -> dict[str, object]:
    return aggregate(
        root,
        run_id="123",
        source_revision=REVISION,
        dependency_status="success",
        runner_os="Linux",
        runner_arch="X64",
    )


def test_bundle_keeps_separate_denominators_and_artifact_hashes(tmp_path: Path) -> None:
    _fixture(tmp_path)
    result = _aggregate(tmp_path)
    assert result["status"] == "completed"
    assert result["run_id"] == "123"
    assert "metrics" not in result
    tracks = result["tracks"]
    assert tracks["scanner"]["metrics"]["fn"] == 1
    assert tracks["dast"]["metrics"]["fn"] == 1
    assert tracks["rag"]["cases_passed"] == 2
    assert tracks["provider_contract"]["providers"]["rag"]["calls"] == 2
    assert tracks["provider_contract"]["providers"]["rag"]["osv_finding_cited"] is True
    assert tracks["dependency_audit"]["measurement"] == "status_only"
    assert tracks["container"]["source_revision_status"] == "unverified"
    assert (
        tracks["api"]["executions"]["gitleaks"]["reported_path_semantics"] == "finding_paths_only"
    )
    assert (
        result["artifact_sha256"]["api/pipeline-api.json"]
        == sha256((tmp_path / "api/pipeline-api.json").read_bytes()).hexdigest()
    )


@pytest.mark.parametrize(
    "component,name",
    [
        ("api", "pipeline-api.json"),
        ("scanner", "multiengine-scanner.json"),
        ("scanner", "rag.json"),
        ("dast", "dast-benchmark.json"),
        ("scanner", "pipeline-contract.json"),
        ("container", "container.manifest.json"),
        ("container", "container.cdx.json"),
        ("history", "history.json"),
    ],
)
def test_missing_component_fails(tmp_path: Path, component: str, name: str) -> None:
    _fixture(tmp_path)
    (tmp_path / component / name).unlink()
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


@pytest.mark.parametrize(
    "component,name,field,value",
    [
        ("api", "pipeline-api.json", "source_revision", "c" * 40),
        ("scanner", "rag.json", "git_revision", "c" * 40),
        ("dast", "dast-benchmark.json", "source_revision", "c" * 40),
    ],
)
def test_stale_component_fails(
    tmp_path: Path, component: str, name: str, field: str, value: str
) -> None:
    _fixture(tmp_path)
    path = tmp_path / component / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    _write(tmp_path, component, name, payload)
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


def test_incomplete_and_duplicate_json_fail(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "api/pipeline-api.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["checks"]["member_isolation"] = False
    _write(tmp_path, "api", "pipeline-api.json", payload)
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)
    path.write_text('{"status":"completed","status":"failed"}', encoding="utf-8")
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


def test_gitleaks_reported_paths_cannot_claim_full_file_receipt(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "api/pipeline-api.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    next(item for item in payload["executions"] if item["engine"] == "gitleaks")[
        "reported_path_semantics"
    ] = "tool_confirmed_scanned_files"
    _write(tmp_path, "api", "pipeline-api.json", payload)

    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


def test_api_benchmark_requires_four_fixture_findings_with_five_engines(tmp_path: Path) -> None:
    _fixture(tmp_path)
    payload = json.loads((tmp_path / "api/pipeline-api.json").read_text(encoding="utf-8"))
    payload["report"]["finding_count"] = 3
    _write(tmp_path, "api", "pipeline-api.json", payload)

    with pytest.raises(PipelineEvidenceError, match="api_report_incomplete"):
        _aggregate(tmp_path)


def test_api_benchmark_requires_python_cross_file_engine(tmp_path: Path) -> None:
    _fixture(tmp_path)
    payload = json.loads((tmp_path / "api/pipeline-api.json").read_text(encoding="utf-8"))
    payload["executions"] = [
        item for item in payload["executions"] if item["engine"] != "python-flow"
    ]
    _write(tmp_path, "api", "pipeline-api.json", payload)

    with pytest.raises(PipelineEvidenceError, match="api_engine_missing"):
        _aggregate(tmp_path)


def test_failed_upstream_dependency_audit_fails(tmp_path: Path) -> None:
    _fixture(tmp_path)
    with pytest.raises(PipelineEvidenceError):
        aggregate(
            tmp_path,
            run_id="123",
            source_revision=REVISION,
            dependency_status="failure",
            runner_os="Linux",
            runner_arch="X64",
        )


def test_osv_finding_requires_rag_citation(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "scanner/pipeline-contract.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["providers"]["rag"]["osv_finding_cited"] = False
    _write(tmp_path, "scanner", "pipeline-contract.json", payload)
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


def test_duplicate_retrieval_calls_fail_contract(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "scanner/pipeline-contract.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["retrieval_calls"]["observed_calls"] = 20
    _write(tmp_path, "scanner", "pipeline-contract.json", payload)

    with pytest.raises(PipelineEvidenceError, match="provider_contract_cache_invalid"):
        _aggregate(tmp_path)


@pytest.mark.parametrize(
    "component,name,field,value",
    [
        ("scanner", "multiengine-scanner.json", ("metrics", "precision"), 0.1),
        ("scanner", "multiengine-scanner.json", ("metrics", "recall"), 0.1),
        ("scanner", "multiengine-scanner.json", ("metrics", "f1"), 0.1),
        ("scanner", "rag.json", ("metrics", "path_match", "value"), 0.1),
        ("dast", "dast-benchmark.json", ("metrics", "precision"), 0.1),
        ("dast", "dast-benchmark.json", ("metrics", "recall"), 0.1),
        ("dast", "dast-benchmark.json", ("metrics", "f1"), 0.1),
    ],
)
def test_inconsistent_derived_metric_fails(
    tmp_path: Path, component: str, name: str, field: tuple[str, ...], value: float
) -> None:
    _fixture(tmp_path)
    payload = json.loads((tmp_path / component / name).read_text(encoding="utf-8"))
    item = payload
    for key in field[:-1]:
        item = item[key]
    item[field[-1]] = value
    _write(tmp_path, component, name, payload)

    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


@pytest.mark.parametrize(
    "component,name,field,value",
    [
        ("scanner", "multiengine-scanner.json", ("coverage", "assessments_unscored"), 1),
        ("scanner", "rag.json", ("passed",), False),
        ("dast", "dast-benchmark.json", ("execution_status", "active"), "partial"),
        ("container", "container.manifest.json", ("execution_status",), "partial"),
        ("history", "history.json", ("findings",), [{"id": "candidate"}]),
        ("scanner", "pipeline-contract.json", ("retrieval_calls", "all_cited"), False),
    ],
)
def test_incomplete_track_fails(
    tmp_path: Path, component: str, name: str, field: tuple[str, ...], value: object
) -> None:
    _fixture(tmp_path)
    path = tmp_path / component / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    item = payload
    for key in field[:-1]:
        item = item[key]
    item[field[-1]] = value
    _write(tmp_path, component, name, payload)
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)


def test_image_artifact_hash_mismatch_fails(tmp_path: Path) -> None:
    _fixture(tmp_path)
    (tmp_path / "container/container.cdx.json").write_text("changed", encoding="utf-8")
    with pytest.raises(PipelineEvidenceError):
        _aggregate(tmp_path)
