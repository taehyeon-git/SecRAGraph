"""Offline Trivy runner for a trusted local saved runtime image."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep

from security_review.container_image.archive import _tar_hash, inspect_image_tar
from security_review.container_image.errors import ImageScanError
from security_review.container_image.parser import (
    MAX_OUTPUT_BYTES,
    ImageGateIdentity,
    parse_trivy_json,
    validate_db_metadata,
    validate_sbom,
)
from security_review.domain.models import Finding, ScanExecution

TRIVY_VERSION = "0.76.1"
MAX_TIMEOUT_SECONDS = 600
_VERSION_LINE = re.compile(r"(?:^|\n)Version: ([0-9.]+)(?:\r?\n|$)")


@dataclass(frozen=True)
class ImageScanResult:
    findings: tuple[Finding, ...]
    execution: ScanExecution
    sbom_bytes: bytes
    gate_identities: tuple[ImageGateIdentity, ...]
    warnings: tuple[str, ...]


def scan_image_tar(
    tar_path: Path,
    *,
    expected_local_id: str,
    trivy_binary: str = "trivy",
    cache_dir: Path,
    timeout_seconds: int = 600,
) -> ImageScanResult:
    """Scan one trusted local tar; DB acquisition occurs before this function."""

    if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ImageScanError("image_scan_invalid_timeout")
    started = monotonic()
    identity = inspect_image_tar(tar_path, expected_local_id=expected_local_id)
    try:
        metadata_path = cache_dir / "db" / "metadata.json"
        if metadata_path.stat().st_size > 1024 * 1024:
            raise ImageScanError("image_db_invalid_metadata")
        db_updated_at = validate_db_metadata(metadata_path.read_bytes())
    except ImageScanError:
        raise
    except OSError as error:
        raise ImageScanError("image_db_missing") from error

    # The trusted CLI supplies the binary, but inherited TRIVY_* settings and
    # proxy variables must not change the explicitly offline scan contract.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("TRIVY_")
        and key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    }
    try:
        version_process = subprocess.run(  # noqa: S603  # nosec B603
            [trivy_binary, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(timeout_seconds, 20),
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ImageScanError("image_tool_unavailable") from error
    version_output = version_process.stdout
    match = _VERSION_LINE.search(version_output.decode("utf-8", errors="replace"))
    if version_process.returncode != 0 or match is None or match.group(1) != TRIVY_VERSION:
        raise ImageScanError("image_tool_wrong_version")

    with tempfile.TemporaryDirectory(prefix="secragraph-image-") as temporary:
        work = Path(temporary)
        raw_report = _scan_format(
            tar_path,
            trivy_binary=trivy_binary,
            cache_dir=cache_dir,
            output=work / "image.json",
            output_format="json",
            timeout_seconds=timeout_seconds,
            env=env,
        )
        sbom_bytes = _scan_format(
            tar_path,
            trivy_binary=trivy_binary,
            cache_dir=cache_dir,
            output=work / "image.cdx.json",
            output_format="cyclonedx",
            timeout_seconds=timeout_seconds,
            env=env,
        )
    if not tar_path.is_file() or _tar_hash(tar_path) != identity.tar_sha256:
        raise ImageScanError("image_archive_changed")
    parsed = parse_trivy_json(raw_report, expected_image_id=identity.config_digest)
    component_count = validate_sbom(sbom_bytes, expected_image_id=identity.config_digest)
    unknown_count = sum(item.upstream_severity == "UNKNOWN" for item in parsed.gate_identities)
    warnings = (
        (f"Trivy reported {unknown_count} findings with UNKNOWN upstream severity.",)
        if unknown_count
        else ()
    )
    execution = ScanExecution(
        engine="trivy",
        kind="container",
        status="completed",
        version=TRIVY_VERSION,
        elapsed_ms=max(0, int((monotonic() - started) * 1000)),
        checks=(
            "image-vulnerabilities",
            "image-configuration",
            "cyclonedx-sbom",
            *parsed.checked_types,
        ),
        image_id=identity.config_digest,
        image_local_id=identity.local_id,
        image_tar_sha256=identity.tar_sha256,
        image_db_updated_at=db_updated_at,
        image_vulnerability_count=parsed.vulnerability_count,
        image_config_count=parsed.config_count,
        sbom_sha256=sha256(sbom_bytes).hexdigest(),
        sbom_component_count=component_count,
    )
    return ImageScanResult(
        findings=parsed.findings,
        execution=execution,
        sbom_bytes=sbom_bytes,
        gate_identities=parsed.gate_identities,
        warnings=warnings,
    )


def _scan_format(
    tar_path: Path,
    *,
    trivy_binary: str,
    cache_dir: Path,
    output: Path,
    output_format: str,
    timeout_seconds: int,
    env: dict[str, str],
) -> bytes:
    args = [
        trivy_binary,
        "image",
        "--input",
        str(tar_path.resolve()),
        "--cache-dir",
        str(cache_dir.resolve()),
        "--scanners",
        "vuln",
        "--image-config-scanners",
        "misconfig",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--offline-scan",
        "--disable-telemetry",
        "--skip-version-check",
        "--format",
        output_format,
        "--output",
        str(output),
        "--timeout",
        f"{timeout_seconds}s",
        "--quiet",
    ]
    try:
        return_code = _bounded_scan_process(
            args, output=output, env=env, timeout_seconds=timeout_seconds
        )
    except OSError as error:
        raise ImageScanError("image_tool_failed") from error
    if return_code != 0:
        raise ImageScanError("image_tool_failed")
    try:
        if not output.is_file() or not 0 < output.stat().st_size <= MAX_OUTPUT_BYTES:
            raise ImageScanError("image_tool_invalid_output")
        return output.read_bytes()
    except ImageScanError:
        raise
    except OSError as error:
        raise ImageScanError("image_tool_invalid_output") from error


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.terminate()
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _bounded_scan_process(
    args: list[str], *, output: Path, env: dict[str, str], timeout_seconds: int
) -> int:
    """Stop a scanner before its output can overrun the bounded work area."""

    process = subprocess.Popen(  # noqa: S603  # nosec B603
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    deadline = monotonic() + timeout_seconds
    try:
        while True:
            try:
                size = output.stat().st_size
            except FileNotFoundError:
                size = 0
            except OSError:
                raise ImageScanError("image_tool_output_unreadable") from None
            if size > MAX_OUTPUT_BYTES:
                raise ImageScanError("image_tool_output_too_large")
            code = process.poll()
            if code is not None:
                return code
            if monotonic() >= deadline:
                raise ImageScanError("image_tool_timeout")
            sleep(0.1)
    finally:
        if process.poll() is None:
            _stop_process(process)
