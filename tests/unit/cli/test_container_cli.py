"""The trusted image CLI publishes only a complete normalized evidence set."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import security_review.cli as cli
import security_review.container_image as image_module
from security_review.domain.models import Confidence, Finding, ScanExecution, Severity

LOCAL_ID = "sha256:" + "a" * 64
CONFIG_ID = "sha256:" + "b" * 64
TAR_HASH = "c" * 64
SBOM_BYTES = b'{"bomFormat":"CycloneDX","specVersion":"1.7"}'
SBOM_HASH = sha256(SBOM_BYTES).hexdigest()


@dataclass(frozen=True)
class _Identity:
    result_type: str = "debian"
    advisory_id: str = "CVE-2026-1234"
    package_identity: str = "pkg:deb/debian/example@1.0"
    installed_version: str = "1.0"
    upstream_severity: str = "HIGH"
    is_config: bool = False


def _fake_result() -> SimpleNamespace:
    return SimpleNamespace(
        findings=(
            Finding(
                id="trivy:test",
                rule_id="CVE-2026-1234",
                category="container_vulnerability",
                severity=Severity.HIGH,
                image_id=CONFIG_ID,
                image_resource="pkg:deb/debian/example@1.0",
                upstream_severity="HIGH",
                severity_source="debian",
                message="Installed package has an advisory.",
                redacted_evidence="example 1.0",
                confidence=Confidence.HIGH,
                remediation="Update the package.",
                engine="trivy",
            ),
        ),
        execution=ScanExecution(
            engine="trivy",
            kind="container",
            status="completed",
            version="0.76.1",
            elapsed_ms=100,
            checks=("os-pkgs", "lang-pkgs", "image-config"),
            image_id=CONFIG_ID,
            image_local_id=LOCAL_ID,
            image_tar_sha256=TAR_HASH,
            image_db_updated_at="2026-10-29T13:09:46Z",
            image_vulnerability_count=1,
            image_config_count=0,
            sbom_sha256=SBOM_HASH,
            sbom_component_count=1,
        ),
        sbom_bytes=SBOM_BYTES,
        gate_identities=(_Identity(),),
        warnings=(),
    )


def _args(tar_path: Path, output: Path, cache: Path) -> list[str]:
    return [
        "scan-image",
        str(tar_path),
        "--image-id",
        LOCAL_ID,
        "--trivy-binary",
        "trivy",
        "--cache-dir",
        str(cache),
        "--output-dir",
        str(output),
        "--offline-evidence",
    ]


def test_scan_image_publishes_one_complete_normalized_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"trusted-fixture")
    cache = tmp_path / "cache"
    cache.mkdir()
    output = tmp_path / "evidence"
    seen: dict[str, object] = {}

    def fake_scan(path: Path, **kwargs: object) -> SimpleNamespace:
        seen.update({"path": path, **kwargs})
        return _fake_result()

    monkeypatch.setattr(image_module, "scan_image_tar", fake_scan)
    result = CliRunner().invoke(cli.app, _args(tar_path, output, cache))

    assert result.exit_code == 0, result.output
    assert seen["path"] == tar_path.resolve()
    assert seen["expected_local_id"] == LOCAL_ID
    assert {path.name for path in output.iterdir()} == {
        "container.json",
        "container.md",
        "container.sarif",
        "container.cdx.json",
        "container.manifest.json",
    }
    report = json.loads((output / "container.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "container.manifest.json").read_text(encoding="utf-8"))
    assert report["findings"][0]["image_id"] == CONFIG_ID
    assert manifest["schema_version"] == 1
    assert manifest["execution_status"] == "completed"
    assert manifest["trivy_version"] == "0.76.1"
    assert manifest["gate_identities"] == [_Identity().__dict__]
    assert manifest["sbom_component_count"] == 1
    assert set(manifest["artifacts"]) == {
        "container.json",
        "container.md",
        "container.sarif",
        "container.cdx.json",
    }
    for filename, digest in manifest["artifacts"].items():
        assert sha256((output / filename).read_bytes()).hexdigest() == digest
    assert (
        sha256((output / "container.cdx.json").read_bytes()).hexdigest() == manifest["sbom_sha256"]
    )


def test_scan_image_error_leaves_no_published_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"trusted-fixture")
    cache = tmp_path / "cache"
    cache.mkdir()
    output = tmp_path / "evidence"

    def fail_scan(_path: Path, **_kwargs: object) -> None:
        raise image_module.ImageScanError("trivy_timeout")

    monkeypatch.setattr(image_module, "scan_image_tar", fail_scan)
    result = CliRunner().invoke(cli.app, _args(tar_path, output, cache))
    assert result.exit_code != 0
    assert not output.exists()
    assert "trivy_timeout" in result.output


def test_scan_image_rejects_finding_from_another_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"trusted-fixture")
    cache = tmp_path / "cache"
    cache.mkdir()
    output = tmp_path / "evidence"
    mismatched = _fake_result()
    mismatched.execution = mismatched.execution.model_copy(
        update={"image_id": "sha256:" + "e" * 64}
    )
    monkeypatch.setattr(image_module, "scan_image_tar", lambda *_args, **_kwargs: mismatched)

    result = CliRunner().invoke(cli.app, _args(tar_path, output, cache))
    assert result.exit_code == 1
    assert not output.exists()


def test_scan_image_refuses_to_overwrite_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"trusted-fixture")
    cache = tmp_path / "cache"
    cache.mkdir()
    output = tmp_path / "evidence"
    output.mkdir()
    (output / "keep.txt").write_text("keep", encoding="utf-8")
    monkeypatch.setattr(
        image_module,
        "scan_image_tar",
        lambda *_args, **_kwargs: pytest.fail("must refuse before scan"),
    )

    result = CliRunner().invoke(cli.app, _args(tar_path, output, cache))
    assert result.exit_code == 2
    assert (output / "keep.txt").read_text(encoding="utf-8") == "keep"
