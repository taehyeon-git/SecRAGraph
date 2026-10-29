"""Gate a complete normalized image scan against reviewed existing debt.

The baseline is deliberately static: CI never rewrites it, and a PR cannot
enlarge it by changing the file in its checkout. Raw Trivy output is not read
or printed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BOOTSTRAP_BASE_SHA = "c8f7800ebd740298478a6c705e51f0c0e04b51f3"
TRIVY_VERSION = "0.76.1"
BASELINE_PATH = Path("data/security/container-image-baseline.json")
MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_IDENTITIES = 10_000
SEVERE = frozenset({"HIGH", "CRITICAL", "UNKNOWN"})
BLOCKING_CONFIG = frozenset({"MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ARTIFACTS = frozenset({"container.json", "container.md", "container.sarif", "container.cdx.json"})
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


class BaselineError(ValueError):
    """The versioned or base-commit policy cannot be trusted."""


class GateError(ValueError):
    """The current scan is incomplete or has malformed gate evidence."""


@dataclass(frozen=True, order=True)
class Identity:
    result_type: str
    advisory_id: str
    package_identity: str
    installed_version: str
    upstream_severity: str
    is_config: bool


@dataclass(frozen=True)
class GateDecision:
    total_severe: int
    baseline_severe: int
    new_severe: tuple[Identity, ...]
    blocking_config: tuple[Identity, ...]

    @property
    def blocked(self) -> bool:
        return bool(self.new_severe or self.blocking_config)


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_json(path: Path, error_type: type[ValueError]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_POLICY_BYTES:
        raise error_type("missing, linked or oversized policy file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_pairs)
    except (OSError, UnicodeError, ValueError) as error:
        raise error_type("invalid policy JSON") from error
    if not isinstance(payload, dict):
        raise error_type("policy must be a JSON object")
    return payload


def _safe_string(value: object, *, max_length: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > max_length or (not value and not allow_empty):
        raise ValueError("invalid gate identity text")
    if any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("gate identity contains controls or whitespace")
    return value


def _identity(value: object) -> Identity:
    if not isinstance(value, dict) or set(value) != {
        "result_type",
        "advisory_id",
        "package_identity",
        "installed_version",
        "upstream_severity",
        "is_config",
    }:
        raise ValueError("invalid identity fields")
    result_type = _safe_string(value["result_type"], max_length=128)
    advisory_id = _safe_string(value["advisory_id"], max_length=128)
    package_identity = _safe_string(value["package_identity"], max_length=1024)
    installed_version = _safe_string(value["installed_version"], max_length=256, allow_empty=True)
    severity = _safe_string(value["upstream_severity"], max_length=16)
    if not _TOKEN.fullmatch(result_type) or not _TOKEN.fullmatch(advisory_id):
        raise ValueError("invalid identity token")
    if severity not in SEVERITIES or type(value["is_config"]) is not bool:
        raise ValueError("invalid identity severity or type")
    if value["is_config"] and installed_version:
        raise ValueError("config identity cannot have an installed package version")
    return Identity(
        result_type,
        advisory_id,
        package_identity,
        installed_version,
        severity,
        value["is_config"],
    )


def _identities(value: object) -> tuple[Identity, ...]:
    if not isinstance(value, list) or len(value) > MAX_IDENTITIES:
        raise ValueError("invalid identity list")
    identities = tuple(_identity(item) for item in value)
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate gate identity")
    return identities


def load_baseline(path: Path) -> dict[str, Any]:
    """Validate the checked-in baseline before comparing it to any result."""

    payload = _load_json(path, BaselineError)
    if (
        set(payload)
        != {"schema_version", "scanner", "scanner_version", "source_revision", "identities"}
        or payload["schema_version"] != 1
        or payload["scanner"] != "trivy"
        or payload["scanner_version"] != TRIVY_VERSION
        or not isinstance(payload["source_revision"], str)
        or payload["source_revision"] != BOOTSTRAP_BASE_SHA
    ):
        raise BaselineError("unsupported baseline schema or version")
    try:
        identities = _identities(payload["identities"])
    except ValueError as error:
        raise BaselineError("invalid baseline identities") from error
    if any(item.is_config or item.upstream_severity not in SEVERE for item in identities):
        raise BaselineError("baseline may contain only severe package vulnerabilities")
    if tuple(sorted(identities)) != identities:
        raise BaselineError("baseline identities must be sorted")
    return payload


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if (
        manifest.get("schema_version") != 1
        or manifest.get("execution_status") != "completed"
        or manifest.get("trivy_version") != TRIVY_VERSION
        or not isinstance(manifest.get("image_id"), str)
        or not _IMAGE_ID.fullmatch(manifest["image_id"])
        or not isinstance(manifest.get("image_local_id"), str)
        or not _IMAGE_ID.fullmatch(manifest["image_local_id"])
    ):
        raise GateError("incomplete or unsupported image scan manifest")
    for field in ("image_tar_sha256", "sbom_sha256"):
        value = manifest.get(field)
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise GateError("invalid image or SBOM digest")
    for field in ("image_vulnerability_count", "image_config_count"):
        value = manifest.get(field)
        if type(value) is not int or value < 0 or value > MAX_IDENTITIES:
            raise GateError("invalid image finding count")
    component_count = manifest.get("sbom_component_count")
    if type(component_count) is not int or not 0 < component_count <= 100_000:
        raise GateError("invalid SBOM component count")
    db_time = manifest.get("db_updated_at")
    try:
        if not isinstance(db_time, str):
            raise ValueError("missing DB time")
        updated = datetime.fromisoformat(db_time.replace("Z", "+00:00"))
        if updated.tzinfo is None:
            raise ValueError("DB time must carry a timezone")
        age = datetime.now(UTC) - updated.astimezone(UTC)
    except (TypeError, ValueError) as error:
        raise GateError("invalid DB timestamp") from error
    if age > timedelta(hours=72) or age < -timedelta(minutes=5):
        raise GateError("stale or future DB timestamp")
    artifacts = manifest.get("artifacts")
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != _ARTIFACTS
        or any(
            not isinstance(item, str) or not _SHA256.fullmatch(item) for item in artifacts.values()
        )
        or artifacts.get("container.cdx.json") != manifest["sbom_sha256"]
    ):
        raise GateError("invalid artifact digest manifest")


def verify_artifacts(manifest: dict[str, Any], *, output_dir: Path) -> None:
    """Verify the four public artifacts without reading the raw Trivy JSON."""

    _validate_manifest(manifest)
    artifacts = manifest["artifacts"]
    for name in sorted(_ARTIFACTS):
        path = output_dir / name
        if (
            path.is_symlink()
            or not path.is_file()
            or not 0 < path.stat().st_size <= MAX_ARTIFACT_BYTES
        ):
            raise GateError("missing, linked or oversized image artifact")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != artifacts[name]:
            raise GateError("image artifact digest mismatch")
    verify_normalized_report(manifest, (output_dir / "container.json").read_bytes())


def _expected_finding_id(identity: Identity) -> str:
    payload = "\0".join(
        (
            identity.result_type,
            identity.advisory_id,
            identity.package_identity,
            identity.installed_version,
            str(identity.is_config),
        )
    )
    return "IMG-" + hashlib.sha256(payload.encode()).hexdigest()[:24]


def verify_normalized_report(manifest: dict[str, Any], raw: bytes) -> None:
    """Bind the gate keys to the actual published findings and execution.

    Artifact hashes alone only establish that files match the manifest. This
    check prevents a manifest from silently omitting a reported finding.
    """

    _validate_manifest(manifest)
    if not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise GateError("missing or oversized normalized report")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_pairs)
        identities = _identities(manifest.get("gate_identities"))
    except (UnicodeError, ValueError) as error:
        raise GateError("invalid normalized image report") from error
    if not isinstance(report, dict) or report.get("status") not in {
        "completed",
        "completed_with_warnings",
    }:
        raise GateError("incomplete normalized image report")
    findings = report.get("findings")
    summary = report.get("summary")
    executions = report.get("executions")
    if (
        not isinstance(findings, list)
        or len(findings) != len(identities)
        or not isinstance(summary, dict)
        or type(summary.get("total")) is not int
        or summary["total"] != len(findings)
        or not isinstance(executions, list)
        or len(executions) != 1
        or not isinstance(executions[0], dict)
    ):
        raise GateError("normalized image report count or execution mismatch")
    execution = executions[0]
    if (
        execution.get("engine") != "trivy"
        or execution.get("kind") != "container"
        or execution.get("status") != "completed"
        or execution.get("version") != manifest["trivy_version"]
        or execution.get("image_id") != manifest["image_id"]
        or execution.get("image_local_id") != manifest["image_local_id"]
        or execution.get("image_tar_sha256") != manifest["image_tar_sha256"]
        or execution.get("image_vulnerability_count") != manifest["image_vulnerability_count"]
        or execution.get("image_config_count") != manifest["image_config_count"]
        or execution.get("sbom_sha256") != manifest["sbom_sha256"]
        or execution.get("sbom_component_count") != manifest["sbom_component_count"]
    ):
        raise GateError("normalized image execution provenance mismatch")
    checks = execution.get("checks")
    if (
        not isinstance(checks, list)
        or any(not isinstance(item, str) for item in checks)
        or not {
            "image-vulnerabilities",
            "image-configuration",
            "cyclonedx-sbom",
            "debian",
            "python-pkg",
            "dockerfile",
        }.issubset(set(checks))
    ):
        raise GateError("normalized image execution coverage mismatch")
    db_time = execution.get("image_db_updated_at")
    try:
        if not isinstance(db_time, str):
            raise ValueError("missing execution DB time")
        execution_db_time = datetime.fromisoformat(db_time.replace("Z", "+00:00"))
        manifest_db_time = datetime.fromisoformat(manifest["db_updated_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError("normalized image DB time mismatch") from error
    if execution_db_time.tzinfo is None or execution_db_time.astimezone(
        UTC
    ) != manifest_db_time.astimezone(UTC):
        raise GateError("normalized image DB time mismatch")

    by_id = {_expected_finding_id(item): item for item in identities}
    if len(by_id) != len(identities):
        raise GateError("colliding image gate identities")
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise GateError("invalid normalized image finding")
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or finding_id in seen:
            raise GateError("duplicate or missing normalized image finding")
        seen.add(finding_id)
        identity = by_id.get(finding_id)
        if identity is None:
            raise GateError("finding missing from image gate identities")
        category = "container_configuration" if identity.is_config else "container_vulnerability"
        severity = (
            "medium"
            if identity.upstream_severity == "UNKNOWN"
            else identity.upstream_severity.lower()
        )
        if (
            finding.get("rule_id") != identity.advisory_id
            or finding.get("category") != category
            or finding.get("severity") != severity
            or finding.get("image_id") != manifest["image_id"]
            or finding.get("image_resource") != identity.package_identity
            or finding.get("upstream_severity") != identity.upstream_severity
            or finding.get("file_path") is not None
            or finding.get("line_start") is not None
            or finding.get("http_method") is not None
            or finding.get("http_path") is not None
            or finding.get("git_commit") is not None
            or finding.get("trace") not in (None, [])
        ):
            raise GateError("normalized image finding disagrees with gate identity")


def evaluate_gate(manifest: dict[str, Any], baseline: dict[str, Any]) -> GateDecision:
    """Keep pre-existing records visible while blocking new severe ones."""

    _validate_manifest(manifest)
    try:
        current = _identities(manifest.get("gate_identities"))
        old = _identities(baseline.get("identities"))
    except ValueError as error:
        raise GateError("invalid current or baseline identities") from error
    if len(current) != manifest["image_vulnerability_count"] + manifest["image_config_count"]:
        raise GateError("image identity count disagrees with reported findings")
    if any(item.is_config or item.upstream_severity not in SEVERE for item in old):
        raise GateError("invalid baseline scope")
    current_severe = {
        item for item in current if not item.is_config and item.upstream_severity in SEVERE
    }
    baseline_severe = set(old)
    blocking_config = tuple(
        sorted(
            item for item in current if item.is_config and item.upstream_severity in BLOCKING_CONFIG
        )
    )
    return GateDecision(
        total_severe=len(current_severe),
        baseline_severe=len(baseline_severe),
        new_severe=tuple(sorted(current_severe - baseline_severe)),
        blocking_config=blocking_config,
    )


def verify_baseline_unchanged(path: Path, *, base_sha: str, repo_root: Path) -> None:
    """Compare PR/push policy bytes against the actual base commit's blob."""

    if not _SHA.fullmatch(base_sha):
        raise BaselineError("invalid base commit SHA")
    expected_path = (repo_root / BASELINE_PATH).resolve()
    if path.is_symlink() or path.resolve() != expected_path:
        raise BaselineError("unexpected baseline path")
    env = os.environ.copy()
    env.update(
        {"GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}
    )
    git = shutil.which("git")
    if git is None:
        raise BaselineError("Git is unavailable")
    try:
        object_type = subprocess.run(  # noqa: S603 - trusted Git executable, fixed argv.
            [git, "-C", str(repo_root), "cat-file", "-t", base_sha],
            capture_output=True,
            check=False,
            timeout=20,
            env=env,
        )
        if object_type.returncode != 0 or object_type.stdout.strip() != b"commit":
            raise BaselineError("base commit is unavailable")
        previous = subprocess.run(  # noqa: S603 - fixed blob path, validated SHA.
            [git, "-C", str(repo_root), "show", f"{base_sha}:{BASELINE_PATH.as_posix()}"],
            capture_output=True,
            check=False,
            timeout=20,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BaselineError("could not read base baseline") from error
    if previous.returncode != 0:
        if base_sha == BOOTSTRAP_BASE_SHA:
            return
        raise BaselineError("base commit has no baseline")
    if len(previous.stdout) > MAX_POLICY_BYTES or previous.stdout != path.read_bytes():
        raise BaselineError("baseline differs from the base commit")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate complete image evidence")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    options = parser.parse_args(argv)
    try:
        baseline = load_baseline(options.baseline)
        verify_baseline_unchanged(
            options.baseline, base_sha=options.base_sha, repo_root=options.repo_root
        )
        manifest = _load_json(options.manifest, GateError)
        verify_artifacts(manifest, output_dir=options.manifest.parent)
        decision = evaluate_gate(manifest, baseline)
    except (BaselineError, GateError, OSError) as error:
        print(f"container_gate_error: {error}", file=sys.stderr)
        return 2
    print(
        "container_gate: "
        f"severe_total={decision.total_severe} "
        f"baseline_records={decision.baseline_severe} "
        f"new_severe={len(decision.new_severe)} "
        f"blocking_config={len(decision.blocking_config)}"
    )
    if decision.blocked:
        # Advisory/package IDs are already in the public normalized report.
        for item in (*decision.new_severe, *decision.blocking_config)[:20]:
            print(f"blocked: {item.advisory_id} {item.package_identity}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
