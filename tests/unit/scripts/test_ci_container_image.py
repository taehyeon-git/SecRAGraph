"""Fail-closed policy tests for the built-image CI gate."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.ci_container_image import (
    BOOTSTRAP_BASE_SHA,
    BaselineError,
    GateError,
    evaluate_gate,
    load_baseline,
    verify_artifacts,
    verify_baseline_unchanged,
    verify_normalized_report,
)


def _identity(*, severity: str = "HIGH", advisory: str = "CVE-2026-1") -> dict[str, object]:
    return {
        "result_type": "debian",
        "advisory_id": advisory,
        "package_identity": "pkg:deb/debian/example@1.0",
        "installed_version": "1.0",
        "upstream_severity": severity,
        "is_config": False,
    }


def _baseline(identities: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scanner": "trivy",
        "scanner_version": "0.76.1",
        "source_revision": BOOTSTRAP_BASE_SHA,
        "identities": identities,
    }


def _manifest(identities: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "execution_status": "completed",
        "trivy_version": "0.76.1",
        "image_id": "sha256:" + "a" * 64,
        "image_local_id": "sha256:" + "b" * 64,
        "image_tar_sha256": "c" * 64,
        "db_updated_at": datetime.now(UTC).isoformat(),
        "image_vulnerability_count": sum(not item["is_config"] for item in identities),
        "image_config_count": sum(item["is_config"] for item in identities),
        "sbom_sha256": "d" * 64,
        "sbom_component_count": 1,
        "artifacts": {
            "container.json": "e" * 64,
            "container.md": "e" * 64,
            "container.sarif": "e" * 64,
            "container.cdx.json": "d" * 64,
        },
        "gate_identities": identities,
    }


def _report(identities: list[dict[str, object]], manifest: dict[str, object]) -> dict[str, object]:
    findings = []
    for item in identities:
        source = "\0".join(
            (
                str(item["result_type"]),
                str(item["advisory_id"]),
                str(item["package_identity"]),
                str(item["installed_version"]),
                str(item["is_config"]),
            )
        )
        findings.append(
            {
                "id": "IMG-" + hashlib.sha256(source.encode()).hexdigest()[:24],
                "rule_id": item["advisory_id"],
                "category": (
                    "container_configuration" if item["is_config"] else "container_vulnerability"
                ),
                "severity": (
                    "medium"
                    if item["upstream_severity"] == "UNKNOWN"
                    else str(item["upstream_severity"]).lower()
                ),
                "image_id": manifest["image_id"],
                "image_resource": item["package_identity"],
                "upstream_severity": item["upstream_severity"],
                "file_path": None,
                "http_path": None,
            }
        )
    return {
        "status": "completed",
        "summary": {"total": len(findings)},
        "findings": findings,
        "executions": [
            {
                "engine": "trivy",
                "kind": "container",
                "status": "completed",
                "version": manifest["trivy_version"],
                "checks": [
                    "image-vulnerabilities",
                    "image-configuration",
                    "cyclonedx-sbom",
                    "debian",
                    "python-pkg",
                    "dockerfile",
                ],
                "image_id": manifest["image_id"],
                "image_local_id": manifest["image_local_id"],
                "image_tar_sha256": manifest["image_tar_sha256"],
                "image_db_updated_at": manifest["db_updated_at"],
                "image_vulnerability_count": manifest["image_vulnerability_count"],
                "image_config_count": manifest["image_config_count"],
                "sbom_sha256": manifest["sbom_sha256"],
                "sbom_component_count": manifest["sbom_component_count"],
            }
        ],
    }


def test_existing_severe_debt_is_reported_without_failing_delta() -> None:
    identity = _identity()
    decision = evaluate_gate(_manifest([identity]), _baseline([identity]))
    assert decision.total_severe == 1
    assert decision.baseline_severe == 1
    assert decision.new_severe == ()


def test_new_advisory_and_severity_escalation_fail() -> None:
    old = _identity()
    new = _identity(advisory="CVE-2026-2")
    elevated = _identity(severity="CRITICAL")
    assert len(evaluate_gate(_manifest([old, new]), _baseline([old])).new_severe) == 1
    assert len(evaluate_gate(_manifest([elevated]), _baseline([old])).new_severe) == 1


def test_removed_baseline_finding_passes() -> None:
    decision = evaluate_gate(_manifest([]), _baseline([_identity()]))
    assert decision.total_severe == 0
    assert decision.new_severe == ()


@pytest.mark.parametrize("severity", ["MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"])
def test_image_config_medium_or_unknown_fails(severity: str) -> None:
    config = {
        "result_type": "dockerfile",
        "advisory_id": "DS001",
        "package_identity": "config:DS001",
        "installed_version": "",
        "upstream_severity": severity,
        "is_config": True,
    }
    decision = evaluate_gate(_manifest([config]), _baseline([]))
    assert len(decision.blocking_config) == 1


@pytest.mark.parametrize(
    "bad_manifest",
    [
        {**_manifest([]), "execution_status": "partial"},
        {**_manifest([]), "trivy_version": "0.0.0"},
        {**_manifest([]), "gate_identities": [_identity(), _identity()]},
        {**_manifest([]), "gate_identities": [{**_identity(), "package_identity": "secret\nkey"}]},
        {**_manifest([]), "sbom_component_count": 0},
        {**_manifest([]), "db_updated_at": "2000-01-01T00:00:00Z"},
    ],
)
def test_incomplete_or_malformed_manifest_fails(bad_manifest: dict[str, object]) -> None:
    with pytest.raises(GateError):
        evaluate_gate(bad_manifest, _baseline([]))


def test_malformed_baseline_fails(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(_baseline([_identity(), _identity()])), encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_artifact_hashes_are_checked(tmp_path: Path) -> None:
    manifest = _manifest([])
    artifacts: dict[str, str] = {}
    for name in manifest["artifacts"]:
        if name == "container.json":
            continue
        payload = name.encode()
        (tmp_path / name).write_bytes(payload)
        artifacts[name] = hashlib.sha256(payload).hexdigest()
    manifest["sbom_sha256"] = artifacts["container.cdx.json"]
    report_bytes = json.dumps(_report([], manifest)).encode()
    (tmp_path / "container.json").write_bytes(report_bytes)
    artifacts["container.json"] = hashlib.sha256(report_bytes).hexdigest()
    manifest["artifacts"] = artifacts
    verify_artifacts(manifest, output_dir=tmp_path)
    (tmp_path / "container.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(GateError, match="digest"):
        verify_artifacts(manifest, output_dir=tmp_path)


def test_report_finding_cannot_be_omitted_from_gate_manifest() -> None:
    manifest = _manifest([])
    report = _report([_identity()], manifest)
    with pytest.raises(GateError):
        verify_normalized_report(manifest, json.dumps(report).encode())


def test_report_finding_identity_and_execution_must_match_manifest() -> None:
    identity = _identity()
    manifest = _manifest([identity])
    report = _report([identity], manifest)
    verify_normalized_report(manifest, json.dumps(report).encode())
    report["findings"][0]["image_resource"] = "pkg:deb/debian/other@2.0"
    with pytest.raises(GateError):
        verify_normalized_report(manifest, json.dumps(report).encode())
    report = _report([identity], manifest)
    report["executions"][0]["image_id"] = "sha256:" + "f" * 64
    with pytest.raises(GateError):
        verify_normalized_report(manifest, json.dumps(report).encode())


def _git(cwd: Path, *args: str) -> str:
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603 - fixed test fixture argv.
        [git, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,  # noqa: S607
    )
    return result.stdout.strip()


def test_pr_baseline_change_is_rejected_against_real_base(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.com")
    path = tmp_path / "data" / "security" / "container-image-baseline.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_baseline([_identity()])), encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base_sha = _git(tmp_path, "rev-parse", "HEAD")
    verify_baseline_unchanged(path, base_sha=base_sha, repo_root=tmp_path)
    path.write_text(json.dumps(_baseline([])), encoding="utf-8")
    with pytest.raises(BaselineError):
        verify_baseline_unchanged(path, base_sha=base_sha, repo_root=tmp_path)


def test_missing_base_baseline_is_not_general_waiver(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.com")
    (tmp_path / "README").write_text("base", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base_sha = _git(tmp_path, "rev-parse", "HEAD")
    path = tmp_path / "data" / "security" / "container-image-baseline.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_baseline([])), encoding="utf-8")
    with pytest.raises(BaselineError):
        verify_baseline_unchanged(path, base_sha=base_sha, repo_root=tmp_path)
