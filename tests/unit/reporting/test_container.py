from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.orchestrator.scan_graph import _rebuild_enriched_finding
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif
from security_review.storage.models import ScanReportRow

CONFIG_DIGEST = "sha256:" + "a" * 64
LOCAL_DIGEST = "sha256:" + "b" * 64
TAR_SHA = "c" * 64
SBOM_SHA = "d" * 64


def _image_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "id": "trivy:pkg:debian:apt:cve-1",
        "rule_id": "CVE-2026-12345",
        "category": "container_vulnerability",
        "severity": Severity.HIGH,
        "image_id": CONFIG_DIGEST,
        "image_resource": "pkg:deb/debian/apt@2.6.1?arch=amd64",
        "upstream_severity": "HIGH",
        "severity_source": "debian",
        "message": "Installed package has a known advisory.",
        "redacted_evidence": "apt 2.6.1; fixed 2.6.2",
        "confidence": Confidence.HIGH,
        "remediation": "Upgrade the package.",
        "engine": "trivy",
    }
    values.update(overrides)
    return Finding.model_validate(values)


def _execution(**overrides: object) -> ScanExecution:
    values: dict[str, object] = {
        "engine": "trivy",
        "kind": "container",
        "status": "completed",
        "version": "0.76.1",
        "elapsed_ms": 1200,
        "image_id": CONFIG_DIGEST,
        "image_local_id": LOCAL_DIGEST,
        "image_tar_sha256": TAR_SHA,
        "image_db_updated_at": datetime(2026, 10, 29, 13, 9, tzinfo=UTC),
        "image_vulnerability_count": 2,
        "image_config_count": 0,
        "sbom_sha256": SBOM_SHA,
        "sbom_component_count": 386,
        "checks": ("os-pkgs", "lang-pkgs", "image-config"),
    }
    values.update(overrides)
    return ScanExecution.model_validate(values)


def test_image_location_is_exclusive_and_validated() -> None:
    finding = _image_finding()
    assert finding.image_id == CONFIG_DIGEST
    assert finding.image_resource == "pkg:deb/debian/apt@2.6.1?arch=amd64"

    for changes in (
        {"file_path": "Dockerfile", "line_start": 2},
        {"http_method": "GET", "http_path": "/health"},
        {"git_commit": "1" * 40},
        {"line_start": 3},
        {"image_id": "sha256:not-a-digest"},
        {"image_resource": "bad\nresource"},
        {"image_resource": "x" * 1025},
    ):
        with pytest.raises(ValidationError):
            _image_finding(**changes)


def test_image_specific_metadata_cannot_be_attached_to_source() -> None:
    with pytest.raises(ValidationError):
        _image_finding(image_id=None, image_resource=None, file_path="app.py", line_start=1)


def test_completed_image_execution_requires_provenance_and_no_source_claim() -> None:
    execution = _execution()
    assert execution.image_db_updated_at == datetime(2026, 10, 29, 13, 9, tzinfo=UTC)

    for changes in (
        {"image_id": None},
        {"sbom_sha256": None},
        {"sbom_component_count": 0},
        {"eligible_files": ("Dockerfile",)},
        {"scanned_files": ("Dockerfile",)},
        {"eligible_endpoints": ("GET /",)},
        {"image_db_updated_at": datetime(2026, 10, 29, 13, 9)},
        {"image_tar_sha256": "C" * 64},
    ):
        with pytest.raises(ValidationError):
            _execution(**changes)

    with pytest.raises(ValidationError):
        _execution(kind="sast")


def test_image_report_has_logical_sarif_location_and_provenance() -> None:
    report = build_report("local-image.tar", [_image_finding()], executions=(_execution(),))
    payload = json.loads(render_json(report))
    markdown = render_markdown(report)
    sarif = json.loads(render_sarif(report, path_prefix="checkout"))["runs"][0]

    finding = payload["findings"][0]
    assert finding["file_path"] is None
    assert finding["image_id"] == CONFIG_DIGEST
    assert finding["upstream_severity"] == "HIGH"
    assert payload["executions"][0]["sbom_component_count"] == 386
    assert "Location: pkg:deb/debian/apt@2.6.1?arch=amd64" in markdown
    assert "Image config digest:" in markdown
    assert "SBOM components: 386" in markdown
    result = sarif["results"][0]
    assert result["locations"] == [
        {
            "logicalLocations": [
                {
                    "name": "pkg:deb/debian/apt@2.6.1?arch=amd64",
                    "fullyQualifiedName": "pkg:deb/debian/apt@2.6.1?arch=amd64",
                }
            ]
        }
    ]
    assert result["properties"]["imageId"] == CONFIG_DIGEST
    assert "physicalLocation" not in json.dumps(result)
    assert "checkout" not in json.dumps(result)


def test_image_fingerprint_changes_with_package_or_config_digest() -> None:
    original = _image_finding()
    changed_package = _image_finding(image_resource="pkg:deb/debian/apt@2.6.2?arch=amd64")
    changed_image = _image_finding(image_id="sha256:" + "e" * 64)
    fingerprints = [
        json.loads(render_sarif(build_report("image", [finding])))["runs"][0]["results"][0][
            "partialFingerprints"
        ]
        for finding in (original, changed_package, changed_image)
    ]
    assert len({json.dumps(value, sort_keys=True) for value in fingerprints}) == 3


def test_graph_rebuild_preserves_image_provenance() -> None:
    original = _image_finding()
    enriched = _rebuild_enriched_finding(
        original, references=original.references, remediation="Upgrade the package."
    )
    assert enriched == original
    assert enriched.image_id == CONFIG_DIGEST
    assert enriched.upstream_severity == "HIGH"


def test_database_row_round_trips_image_location_and_execution() -> None:
    report = build_report("image", [_image_finding()], executions=(_execution(),))
    row = ScanReportRow.from_domain(report)
    restored = row.to_domain()
    assert row.findings[0].image_id == CONFIG_DIGEST
    assert restored == report
