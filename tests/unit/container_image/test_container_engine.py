"""Trusted image-tar inspection and bounded Trivy normalization contracts."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from security_review.container_image import (
    ImageScanError,
    inspect_image_tar,
    parse_trivy_json,
    runner,
    validate_db_metadata,
    validate_sbom,
)
from security_review.domain.models import Severity


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _archive(
    tmp_path: Path, *, platform: str = "linux/amd64", two_manifests: bool = False
) -> tuple[Path, str, str]:
    os_name, arch = platform.split("/")
    config = _json({"architecture": arch, "os": os_name, "config": {"Env": ["TOKEN=private"]}})
    config_hash = sha256(config).hexdigest()
    manifest = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_hash}",
                "size": len(config),
            },
            "layers": [],
        }
    )
    manifest_hash = sha256(manifest).hexdigest()
    descriptors = [
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{manifest_hash}",
            "size": len(manifest),
            "platform": {"os": os_name, "architecture": arch},
        }
    ]
    if two_manifests:
        descriptors.append(dict(descriptors[0]))
    index = _json({"schemaVersion": 2, "manifests": descriptors})
    legacy = _json([{"Config": f"blobs/sha256/{config_hash}", "RepoTags": None, "Layers": []}])
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        for name, contents in (
            (f"blobs/sha256/{config_hash}", config),
            (f"blobs/sha256/{manifest_hash}", manifest),
            ("index.json", index),
            ("manifest.json", legacy),
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        ):
            entry = tarfile.TarInfo(name)
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    return path, f"sha256:{manifest_hash}", f"sha256:{config_hash}"


def _report(image_id: str, *, results: list[dict[str, object]] | None = None) -> bytes:
    if results is None:
        results = [
            {
                "Class": "os-pkgs",
                "Type": "debian",
                "Target": "image.tar (debian 12.15)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-12345",
                        "PkgName": "libexample",
                        "PkgIdentifier": {"PURL": "pkg:deb/debian/libexample@1.0?arch=amd64"},
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Severity": "HIGH",
                        "SeveritySource": "debian",
                        "CweIDs": ["CWE-20"],
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                        "Description": "DO_NOT_COPY_PRIVATE_DESCRIPTION",
                    }
                ],
            },
            {"Class": "lang-pkgs", "Type": "python-pkg", "Target": "Python"},
            {"Class": "config", "Type": "dockerfile", "Target": "image.tar"},
        ]
    return _json(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.76.1"},
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": image_id, "ImageConfig": {"Env": ["TOKEN=private"]}},
            "Results": results,
        }
    )


def _sbom(image_id: str, *, components: list[dict[str, str]] | None = None) -> bytes:
    return _json(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {
                "component": {
                    "type": "container",
                    "name": "image.tar",
                    "properties": [{"name": "aquasecurity:trivy:ImageID", "value": image_id}],
                }
            },
            "components": components
            if components is not None
            else [{"type": "library", "name": "x"}],
        }
    )


def test_tar_identity_requires_verified_single_linux_amd64_manifest(tmp_path: Path) -> None:
    path, local_id, config_id = _archive(tmp_path)
    identity = inspect_image_tar(path, expected_local_id=local_id)
    assert identity.local_id == local_id
    assert identity.config_digest == config_id
    assert identity.tar_sha256 == sha256(path.read_bytes()).hexdigest()


def test_tar_identity_rejects_wrong_local_id_and_ambiguous_manifest(tmp_path: Path) -> None:
    path, local_id, _ = _archive(tmp_path)
    with pytest.raises(ImageScanError):
        inspect_image_tar(path, expected_local_id="sha256:" + "0" * 64)
    path, _, _ = _archive(tmp_path, two_manifests=True)
    with pytest.raises(ImageScanError):
        inspect_image_tar(path, expected_local_id=local_id)


def test_tar_identity_rejects_wrong_platform(tmp_path: Path) -> None:
    path, local_id, _ = _archive(tmp_path, platform="linux/arm64")
    with pytest.raises(ImageScanError):
        inspect_image_tar(path, expected_local_id=local_id)


def test_tar_identity_accepts_legacy_docker_config_name(tmp_path: Path) -> None:
    config = _json(
        {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"diff_ids": []}}
    )
    config_hash = sha256(config).hexdigest()
    manifest = _json([{"Config": f"{config_hash}.json", "RepoTags": None, "Layers": []}])
    path = tmp_path / "legacy.tar"
    with tarfile.open(path, "w") as archive:
        for name, contents in ((f"{config_hash}.json", config), ("manifest.json", manifest)):
            entry = tarfile.TarInfo(name)
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    identity = inspect_image_tar(path, expected_local_id=f"sha256:{config_hash}")
    assert identity.config_digest == f"sha256:{config_hash}"


def test_legacy_docker_tar_rejects_changed_layer_with_same_config_id(tmp_path: Path) -> None:
    intended_layer = b"original layer bytes"
    changed_layer = b"tampered layer bytes"
    config = _json(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"diff_ids": [f"sha256:{sha256(intended_layer).hexdigest()}"]},
        }
    )
    config_hash = sha256(config).hexdigest()
    manifest = _json(
        [{"Config": f"{config_hash}.json", "RepoTags": None, "Layers": ["layer/layer.tar"]}]
    )
    path = tmp_path / "legacy-changed.tar"
    with tarfile.open(path, "w") as archive:
        for name, contents in (
            (f"{config_hash}.json", config),
            ("manifest.json", manifest),
            ("layer/layer.tar", changed_layer),
        ):
            entry = tarfile.TarInfo(name)
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    with pytest.raises(ImageScanError, match="image_archive_invalid_layers"):
        inspect_image_tar(path, expected_local_id=f"sha256:{config_hash}")


def test_tar_identity_rejects_dot_entry_with_code_only_error(tmp_path: Path) -> None:
    path, local_id, _ = _archive(tmp_path)
    with tarfile.open(path, "a") as archive:
        entry = tarfile.TarInfo(".")
        entry.type = tarfile.DIRTYPE
        archive.addfile(entry)
    with pytest.raises(ImageScanError, match="image_archive_invalid_entries"):
        inspect_image_tar(path, expected_local_id=local_id)


def test_trivy_normalizes_vulnerability_without_raw_image_config_or_description() -> None:
    image_id = "sha256:" + "a" * 64
    parsed = parse_trivy_json(_report(image_id), expected_image_id=image_id)
    assert parsed.vulnerability_count == 1
    assert parsed.config_count == 0
    finding = parsed.findings[0]
    assert finding.image_id == image_id
    assert finding.rule_id == "CVE-2026-12345"
    assert finding.severity is Severity.HIGH
    assert finding.image_resource == "pkg:deb/debian/libexample@1.0?arch=amd64"
    assert finding.cwe_ids == ("CWE-20",)
    assert "DO_NOT_COPY" not in finding.model_dump_json()
    assert "TOKEN=private" not in finding.model_dump_json()
    assert parsed.gate_identities[0].package_identity == finding.image_resource
    assert parsed.gate_identities[0].is_config is False


def test_unknown_severity_is_explicit_and_conservative() -> None:
    image_id = "sha256:" + "a" * 64
    report = json.loads(_report(image_id))
    report["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
    parsed = parse_trivy_json(_json(report), expected_image_id=image_id)
    assert parsed.findings[0].severity is Severity.MEDIUM
    assert parsed.findings[0].upstream_severity == "UNKNOWN"
    assert parsed.gate_identities[0].upstream_severity == "UNKNOWN"


def test_parser_rejects_bidi_control_in_package_identity() -> None:
    image_id = "sha256:" + "a" * 64
    report = json.loads(_report(image_id))
    report["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]["PURL"] += "\u202e"
    with pytest.raises(ImageScanError, match="image_report_invalid_field"):
        parse_trivy_json(_json(report), expected_image_id=image_id)


def test_parser_normalizes_image_config_finding_without_raw_cause() -> None:
    image_id = "sha256:" + "a" * 64
    report = json.loads(_report(image_id))
    report["Results"][2]["Misconfigurations"] = [
        {
            "ID": "DS001",
            "Severity": "UNKNOWN",
            "CauseMetadata": {"Code": "DO_NOT_COPY_SECRET"},
        }
    ]
    parsed = parse_trivy_json(_json(report), expected_image_id=image_id)
    finding = next(item for item in parsed.findings if item.category == "container_configuration")
    assert finding.image_resource == "config:DS001"
    assert finding.upstream_severity == "UNKNOWN"
    assert parsed.config_count == 1
    assert next(item for item in parsed.gate_identities if item.is_config).advisory_id == "DS001"
    assert "DO_NOT_COPY_SECRET" not in finding.model_dump_json()


def test_empty_or_missing_required_result_class_fails_closed() -> None:
    image_id = "sha256:" + "a" * 64
    with pytest.raises(ImageScanError):
        parse_trivy_json(_report(image_id, results=[]), expected_image_id=image_id)
    with pytest.raises(ImageScanError):
        parse_trivy_json(
            _report(image_id, results=[{"Class": "config", "Type": "dockerfile"}]),
            expected_image_id=image_id,
        )


def test_explicit_null_vulnerability_list_is_not_clean() -> None:
    image_id = "sha256:" + "a" * 64
    report = json.loads(_report(image_id))
    report["Results"][0]["Vulnerabilities"] = None
    with pytest.raises(ImageScanError, match="image_report_invalid_result"):
        parse_trivy_json(_json(report), expected_image_id=image_id)


def test_sbom_must_identify_same_image_and_have_components() -> None:
    image_id = "sha256:" + "a" * 64
    assert validate_sbom(_sbom(image_id), expected_image_id=image_id) == 1
    with pytest.raises(ImageScanError):
        validate_sbom(_sbom("sha256:" + "b" * 64), expected_image_id=image_id)
    with pytest.raises(ImageScanError):
        validate_sbom(_sbom(image_id, components=[]), expected_image_id=image_id)
    with pytest.raises(ImageScanError):
        validate_sbom(_sbom(image_id, components=[{}]), expected_image_id=image_id)


def test_db_metadata_requires_recent_nonfuture_update() -> None:
    now = datetime(2026, 10, 30, 0, 0, tzinfo=UTC)
    good = _json({"Version": 2, "UpdatedAt": (now - timedelta(hours=2)).isoformat()})
    assert validate_db_metadata(good, now=now) == now - timedelta(hours=2)
    stale = _json({"Version": 2, "UpdatedAt": (now - timedelta(hours=73)).isoformat()})
    future = _json({"Version": 2, "UpdatedAt": (now + timedelta(minutes=6)).isoformat()})
    for bad in (stale, future, b"{}"):
        with pytest.raises(ImageScanError):
            validate_db_metadata(bad, now=now)


def test_runner_uses_pinned_offline_trivy_and_binds_report_to_tar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path, local_id, config_id = _archive(tmp_path)
    cache = tmp_path / "cache" / "db"
    cache.mkdir(parents=True)
    (cache / "metadata.json").write_bytes(
        _json({"Version": 2, "UpdatedAt": datetime.now(UTC).isoformat()})
    )
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        assert args[1] == "--version"
        return subprocess.CompletedProcess(args, 0, b"Version: 0.76.1\n", b"")

    def fake_scan(
        args: list[str], *, output: Path, env: dict[str, str], timeout_seconds: int
    ) -> int:
        del env, timeout_seconds
        calls.append(args)
        assert args[:3] == ["trivy", "image", "--input"]
        assert "--offline-scan" in args
        assert "--skip-db-update" in args
        assert "--skip-java-db-update" in args
        assert "--skip-check-update" in args
        assert "--disable-telemetry" in args
        assert "--skip-version-check" in args
        assert "--image-config-scanners" in args
        assert Path(args[args.index("--output") + 1]) == output
        output.write_bytes(
            _report(config_id) if args[args.index("--format") + 1] == "json" else _sbom(config_id)
        )
        return 0

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "_bounded_scan_process", fake_scan)
    result = runner.scan_image_tar(
        tar_path,
        expected_local_id=local_id,
        trivy_binary="trivy",
        cache_dir=cache.parent,
    )
    assert len(calls) == 2
    assert result.execution.status == "completed"
    assert result.execution.image_id == config_id
    assert result.execution.image_local_id == local_id
    assert result.execution.sbom_component_count == 1
    assert result.execution.image_vulnerability_count == 1
    assert len(result.findings) == 1
    assert result.gate_identities[0].advisory_id == "CVE-2026-12345"


def test_runner_fails_closed_on_tool_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tar_path, local_id, _ = _archive(tmp_path)
    cache = tmp_path / "cache" / "db"
    cache.mkdir(parents=True)
    (cache / "metadata.json").write_bytes(
        _json({"Version": 2, "UpdatedAt": datetime.now(UTC).isoformat()})
    )

    def fake_run(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        assert args[1] == "--version"
        return subprocess.CompletedProcess(args, 0, b"Version: 0.76.1\n", b"")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "_bounded_scan_process", lambda *_args, **_kwargs: 1)
    with pytest.raises(ImageScanError) as error:
        runner.scan_image_tar(tar_path, expected_local_id=local_id, cache_dir=cache.parent)
    assert "TOKEN=private" not in str(error.value)


def test_runner_stops_process_while_output_exceeds_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "growing.json"
    stopped: list[bool] = []

    class FakeProcess:
        def __init__(self) -> None:
            output.write_bytes(b"12345678901")
            self.terminated = False

        def poll(self) -> int | None:
            return 1 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True
            stopped.append(True)

        def wait(self, *, timeout: int) -> int:
            assert timeout > 0
            return 1

    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", 10)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    with pytest.raises(ImageScanError, match="image_tool_output_too_large"):
        runner._bounded_scan_process(["trivy", "image"], output=output, env={}, timeout_seconds=10)
    assert stopped == [True]


def test_runner_reaps_process_when_output_metadata_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "unreadable.json"
    output.write_bytes(b"data")
    stopped: list[bool] = []

    class FakeProcess:
        terminated = False

        def poll(self) -> int | None:
            return 1 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True
            stopped.append(True)

        def wait(self, *, timeout: int) -> int:
            assert timeout > 0
            return 1

    original_stat = Path.stat

    def bad_stat(path: Path, *args: object, **kwargs: object) -> object:
        if path == output:
            raise PermissionError("do not leak source path")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    monkeypatch.setattr(Path, "stat", bad_stat)
    with pytest.raises(ImageScanError, match="image_tool_output_unreadable"):
        runner._bounded_scan_process(["trivy", "image"], output=output, env={}, timeout_seconds=10)
    assert stopped == [True]
