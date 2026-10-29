"""Bounded, allowlisted conversion of Trivy output to canonical findings."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal, cast
from urllib.parse import quote, urlsplit

from pydantic import ValidationError

from security_review.container_image.errors import ImageScanError
from security_review.domain.models import Confidence, Finding, Severity, SourceReference

MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 10_000
MAX_COMPONENTS = 100_000
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "UNKNOWN": Severity.MEDIUM,
}
_REFERENCE_HOSTS = {
    "avd.aquasec.com",
    "nvd.nist.gov",
    "osv.dev",
    "github.com",
    "security-tracker.debian.org",
}
UpstreamSeverity = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(frozen=True)
class ImageGateIdentity:
    """Stable candidate key independent of tar path, image digest, and order."""

    result_type: str
    advisory_id: str
    package_identity: str
    installed_version: str
    upstream_severity: UpstreamSeverity
    is_config: bool


@dataclass(frozen=True)
class ParsedImageReport:
    findings: tuple[Finding, ...]
    gate_identities: tuple[ImageGateIdentity, ...]
    vulnerability_count: int
    config_count: int
    checked_types: tuple[str, ...]


def _bounded_json(raw: bytes, error_code: str) -> Any:
    if not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise ImageScanError(error_code)
    try:
        return json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise ImageScanError(error_code) from error


def _bounded_text(value: object, *, limit: int, allow_space: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or any(not (32 if allow_space else 33) <= ord(char) <= 126 for char in value)
    ):
        raise ImageScanError("image_report_invalid_field")
    return value


def _result_type(value: object) -> str:
    if not isinstance(value, str) or not _TYPE.fullmatch(value):
        raise ImageScanError("image_report_invalid_type")
    return value


def _rule_id(value: object) -> str:
    if not isinstance(value, str) or not _RULE.fullmatch(value):
        raise ImageScanError("image_report_invalid_rule")
    return value


def _severity(value: object) -> tuple[Severity, UpstreamSeverity]:
    if not isinstance(value, str) or value not in _SEVERITY:
        raise ImageScanError("image_report_invalid_severity")
    return _SEVERITY[value], cast(UpstreamSeverity, value)


def _cwe_ids(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > 32:
        raise ImageScanError("image_report_invalid_cwe")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _CWE.fullmatch(item):
            raise ImageScanError("image_report_invalid_cwe")
        if item not in normalized:
            normalized.append(item)
    return tuple(normalized)


def _advisory_reference(value: object, advisory_id: str) -> tuple[SourceReference, ...]:
    if not isinstance(value, str) or len(value) > 512:
        return ()
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ()
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _REFERENCE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        return ()
    return (SourceReference(id=advisory_id, title="Advisory", source_url=value),)


def _package_identity(result_type: str, target: object, package: object) -> tuple[str, str, str]:
    if not isinstance(package, dict):
        raise ImageScanError("image_report_invalid_package")
    name = _bounded_text(package.get("PkgName"), limit=256)
    installed = _bounded_text(package.get("InstalledVersion"), limit=128)
    identifier = package.get("PkgIdentifier")
    purl = identifier.get("PURL") if isinstance(identifier, dict) else None
    if purl is not None:
        resource = _bounded_text(purl, limit=1024)
        if not resource.startswith("pkg:"):
            raise ImageScanError("image_report_invalid_package")
    else:
        resource = f"pkg:{result_type}/{quote(name, safe='')}@{quote(installed, safe='')}"
    if result_type == "gobinary":
        binary = _bounded_text(target, limit=512)
        normalized = binary.replace("\\", "/")
        if (
            normalized.startswith("/")
            or ":" in normalized.split("/", 1)[0]
            or ".." in normalized.split("/")
        ):
            raise ImageScanError("image_report_invalid_target")
        resource = f"binary:{normalized}#{resource}"
    if len(resource) > 1024:
        raise ImageScanError("image_report_invalid_package")
    return resource, name, installed


def _finding_id(identity: ImageGateIdentity) -> str:
    payload = "\0".join(
        (
            identity.result_type,
            identity.advisory_id,
            identity.package_identity,
            identity.installed_version,
            str(identity.is_config),
        )
    )
    return "IMG-" + sha256(payload.encode()).hexdigest()[:24]


def _vulnerability(
    value: object, *, result_type: str, target: object, image_id: str
) -> tuple[Finding, ImageGateIdentity]:
    if not isinstance(value, dict):
        raise ImageScanError("image_report_invalid_vulnerability")
    advisory_id = _rule_id(value.get("VulnerabilityID"))
    resource, package_name, installed = _package_identity(result_type, target, value)
    severity, upstream = _severity(value.get("Severity"))
    severity_source = value.get("SeveritySource") or "trivy"
    if not isinstance(severity_source, str) or not _TYPE.fullmatch(severity_source):
        raise ImageScanError("image_report_invalid_severity_source")
    fixed = value.get("FixedVersion")
    if fixed is not None and fixed != "":
        fixed = _bounded_text(fixed, limit=256, allow_space=True)
    else:
        fixed = None
    identity = ImageGateIdentity(result_type, advisory_id, resource, installed, upstream, False)
    remediation = (
        f"Update {package_name} to {fixed} and rebuild the image."
        if fixed
        else f"Review {package_name} and rebuild when a fixed package is available."
    )
    try:
        finding = Finding(
            id=_finding_id(identity),
            rule_id=advisory_id,
            category="container_vulnerability",
            severity=severity,
            image_id=image_id,
            image_resource=resource,
            upstream_severity=upstream,
            severity_source=severity_source,
            message=f"Vulnerable image package: {package_name} ({advisory_id})",
            redacted_evidence=(
                f"Installed {package_name} {installed}; Trivy severity {upstream}"
                f" from {severity_source}."
            ),
            confidence=Confidence.HIGH,
            cwe_ids=_cwe_ids(value.get("CweIDs")),
            remediation=remediation,
            references=_advisory_reference(value.get("PrimaryURL"), advisory_id),
            engine="trivy",
        )
    except ValidationError:
        raise ImageScanError("image_report_invalid_finding") from None
    return finding, identity


def _config_finding(
    value: object, *, result_type: str, image_id: str
) -> tuple[Finding, ImageGateIdentity]:
    if not isinstance(value, dict):
        raise ImageScanError("image_report_invalid_config")
    advisory_id = _rule_id(value.get("ID"))
    severity, upstream = _severity(value.get("Severity"))
    resource = f"config:{advisory_id}"
    identity = ImageGateIdentity(result_type, advisory_id, resource, "", upstream, True)
    try:
        finding = Finding(
            id=_finding_id(identity),
            rule_id=advisory_id,
            category="container_configuration",
            severity=severity,
            image_id=image_id,
            image_resource=resource,
            upstream_severity=upstream,
            severity_source="trivy",
            message=f"Image configuration issue: {advisory_id}",
            redacted_evidence=f"Trivy image-config check {advisory_id}; severity {upstream}.",
            confidence=Confidence.HIGH,
            remediation="Review the image configuration and rebuild the runtime image.",
            engine="trivy",
        )
    except ValidationError:
        raise ImageScanError("image_report_invalid_finding") from None
    return finding, identity


def parse_trivy_json(raw: bytes, *, expected_image_id: str) -> ParsedImageReport:
    """Normalize image findings without copying arbitrary scanner evidence."""

    if not _IMAGE_ID.fullmatch(expected_image_id):
        raise ImageScanError("image_report_invalid_identity")
    report = _bounded_json(raw, "image_report_invalid_json")
    if (
        not isinstance(report, dict)
        or report.get("ArtifactType") != "container_image"
        or report.get("SchemaVersion") != 2
        or not isinstance(report.get("Metadata"), dict)
        or report["Metadata"].get("ImageID") != expected_image_id
        or not isinstance(report.get("Trivy"), dict)
        or report["Trivy"].get("Version") != "0.76.1"
    ):
        raise ImageScanError("image_report_invalid_metadata")
    results = report.get("Results")
    if not isinstance(results, list) or not results or len(results) > 1_000:
        raise ImageScanError("image_report_incomplete")
    seen_classes: set[str] = set()
    checked_types: set[str] = set()
    findings: list[Finding] = []
    identities: list[ImageGateIdentity] = []
    seen_ids: set[str] = set()
    vulnerability_count = 0
    config_count = 0
    for result in results:
        if not isinstance(result, dict) or result.get("Class") not in {
            "os-pkgs",
            "lang-pkgs",
            "config",
        }:
            raise ImageScanError("image_report_invalid_result")
        result_class = str(result["Class"])
        result_type = _result_type(result.get("Type"))
        seen_classes.add(result_class)
        checked_types.add(result_type)
        vulnerabilities = result.get("Vulnerabilities", [])
        configurations = result.get("Misconfigurations", [])
        if not isinstance(vulnerabilities, list) or not isinstance(configurations, list):
            raise ImageScanError("image_report_invalid_result")
        if result_class == "config" and vulnerabilities:
            raise ImageScanError("image_report_invalid_result")
        if result_class != "config" and configurations:
            raise ImageScanError("image_report_invalid_result")
        for value in vulnerabilities:
            finding, identity = _vulnerability(
                value,
                result_type=result_type,
                target=result.get("Target"),
                image_id=expected_image_id,
            )
            vulnerability_count += 1
            if finding.id in seen_ids:
                raise ImageScanError("image_report_duplicate_finding")
            seen_ids.add(finding.id)
            findings.append(finding)
            identities.append(identity)
        for value in configurations:
            finding, identity = _config_finding(
                value, result_type=result_type, image_id=expected_image_id
            )
            config_count += 1
            if finding.id in seen_ids:
                raise ImageScanError("image_report_duplicate_finding")
            seen_ids.add(finding.id)
            findings.append(finding)
            identities.append(identity)
        if len(findings) > MAX_FINDINGS:
            raise ImageScanError("image_report_too_many_findings")
    if seen_classes != {"os-pkgs", "lang-pkgs", "config"} or "python-pkg" not in checked_types:
        raise ImageScanError("image_report_incomplete")
    return ParsedImageReport(
        findings=tuple(findings),
        gate_identities=tuple(identities),
        vulnerability_count=vulnerability_count,
        config_count=config_count,
        checked_types=tuple(sorted(checked_types)),
    )


def validate_sbom(raw: bytes, *, expected_image_id: str) -> int:
    """Require CycloneDX components for the same image config as Trivy JSON."""

    sbom = _bounded_json(raw, "image_sbom_invalid_json")
    if (
        not isinstance(sbom, dict)
        or sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") not in {"1.4", "1.5", "1.6", "1.7"}
    ):
        raise ImageScanError("image_sbom_invalid_metadata")
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    properties = component.get("properties") if isinstance(component, dict) else None
    if (
        not isinstance(component, dict)
        or component.get("type") != "container"
        or not isinstance(properties, list)
    ):
        raise ImageScanError("image_sbom_invalid_metadata")
    image_ids = [
        item.get("value")
        for item in properties
        if isinstance(item, dict) and item.get("name") == "aquasecurity:trivy:ImageID"
    ]
    if image_ids != [expected_image_id]:
        raise ImageScanError("image_sbom_identity_mismatch")
    components = sbom.get("components")
    if not isinstance(components, list) or not 0 < len(components) <= MAX_COMPONENTS:
        raise ImageScanError("image_sbom_incomplete")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("type"), str)
        or not isinstance(item.get("name"), str)
        or not item["type"]
        or not item["name"]
        or len(item["name"]) > 1_024
        for item in components
    ):
        raise ImageScanError("image_sbom_incomplete")
    return len(components)


def validate_db_metadata(raw: bytes, *, now: datetime | None = None) -> datetime:
    """Use an explicitly downloaded and sufficiently fresh Trivy DB."""

    metadata = _bounded_json(raw, "image_db_invalid_metadata")
    if not isinstance(metadata, dict) or metadata.get("Version") != 2:
        raise ImageScanError("image_db_invalid_metadata")
    updated = metadata.get("UpdatedAt")
    if not isinstance(updated, str):
        raise ImageScanError("image_db_invalid_metadata")
    try:
        timestamp = datetime.fromisoformat(updated.replace("Z", "+00:00"))
    except ValueError as error:
        raise ImageScanError("image_db_invalid_metadata") from error
    if timestamp.tzinfo is None:
        raise ImageScanError("image_db_invalid_metadata")
    timestamp = timestamp.astimezone(UTC)
    current = now or datetime.now(UTC)
    if timestamp > current + timedelta(minutes=5) or timestamp < current - timedelta(hours=72):
        raise ImageScanError("image_db_stale")
    return timestamp
