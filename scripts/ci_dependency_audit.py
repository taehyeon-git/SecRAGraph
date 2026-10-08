"""Fail closed when pip-audit cannot verify the installed locked environment."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Literal

AuditStatus = Literal["clean", "vulnerabilities_found", "audit_unavailable"]


@dataclass(frozen=True)
class AuditResult:
    status: AuditStatus
    exit_code: int
    vulnerability_count: int = 0


def classify_audit_result(*, returncode: int, stdout: str, stderr: str) -> AuditResult:
    """Trust a complete JSON report only when the auditor completed normally."""

    # Do not print stderr: an upstream diagnostic could include a private index URL.
    del stderr
    if returncode not in (0, 1):
        return AuditResult("audit_unavailable", 2)

    try:
        payload = json.loads(stdout)
        if not isinstance(payload, dict):
            raise ValueError("audit report must be an object")
        dependencies = payload["dependencies"]
        if not isinstance(dependencies, list) or not dependencies:
            raise ValueError("audit report has no dependencies")
        vulnerability_count = 0
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise ValueError("invalid dependency")
            if not isinstance(dependency.get("name"), str) or not isinstance(
                dependency.get("version"), str
            ):
                raise ValueError("dependency has no identity")
            vulnerabilities = dependency["vulns"]
            if not isinstance(vulnerabilities, list):
                raise ValueError("invalid vulnerability list")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict) or not isinstance(
                    vulnerability.get("id"), str
                ):
                    raise ValueError("invalid vulnerability")
            vulnerability_count += len(vulnerabilities)
    except (ValueError, KeyError, TypeError):
        return AuditResult("audit_unavailable", 2)

    if vulnerability_count:
        return AuditResult("vulnerabilities_found", 1, vulnerability_count)
    if returncode != 0:
        return AuditResult("audit_unavailable", 2)
    return AuditResult("clean", 0)


def main() -> int:
    """Audit the frozen uv environment without exposing upstream diagnostics."""

    executable = shutil.which("pip-audit")
    if executable is None:
        print("audit_unavailable", file=sys.stderr)
        return 2
    try:
        process = subprocess.run(  # noqa: S603 - fixed auditor command, no shell.
            [
                executable,
                "--strict",
                "--desc",
                "--format",
                "json",
                "--vulnerability-service",
                "osv",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("audit_unavailable", file=sys.stderr)
        return 2

    result = classify_audit_result(
        returncode=process.returncode,
        stdout=process.stdout,
        stderr=process.stderr,
    )
    if result.status == "vulnerabilities_found":
        print(f"vulnerabilities_found: {result.vulnerability_count}", file=sys.stderr)
    elif result.status == "audit_unavailable":
        print("audit_unavailable", file=sys.stderr)
    else:
        print("audit_clean")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
