"""Exercise injected OSV, CWE and RAG ports through the real scan service.

This is a synthetic adapter contract, not a live provider or detector accuracy test.
Target bytes are inert and are never imported or executed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Any, cast
from uuid import UUID

from security_review.application import ScanService
from security_review.domain.models import (
    Confidence,
    Finding,
    ScanExecution,
    Severity,
    SourceReference,
)
from security_review.intelligence.dependency_osv import (
    DependencyCoordinate,
    LiveDependencyAuditor,
)
from security_review.intelligence.dynamic_cwe import CweEvidenceResult
from security_review.intelligence.models import DocumentChunk
from security_review.intelligence.osv import OsvAdvisory
from security_review.orchestrator.scan_graph import (
    DeterministicScanResult,
    ScanGraphServices,
    ScanRequest,
)
from security_review.storage.memory import InMemoryReportRepository

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = b"eval(input())\n"
_LOCK = (
    b'version = 1\n[[package]]\nname = "pipeline-fixture-pkg"\nversion = "1.0.0"\n'
    b'source = { registry = "https://pypi.org/simple" }\n'
)
_OWNER = UUID("00000000-0000-4000-8000-000000000001")
_CWE_REF = SourceReference(
    id="mitre:CWE-95",
    title="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
    source_url="https://cwe-api.mitre.org/api/v1/cwe/weakness/95",
)
_CHUNK = DocumentChunk(
    id="fixture:guide:1",
    title="Synthetic guidance",
    text="Use a safe parser for untrusted expressions.",
    source_url="https://example.invalid/fixture/guide",
    section="Parsing",
    score=0.9,
)
_ADVISORY = OsvAdvisory(
    id="OSV-TEST-0001",
    cve_ids=(),
    summary="Synthetic advisory; no real vulnerability is asserted.",
    published_at=None,
    source_url="https://osv.dev/vulnerability/OSV-TEST-0001",
)
_LIMITATIONS = (
    "Synthetic adapter contract only; no live OSV, MITRE, Qdrant or LLM request.",
    "The SAST finding is a controlled fixture, not a detector accuracy observation.",
    "The cited source URLs are fixture metadata, not verified live documents.",
)


class _FixtureQueryer:
    def __init__(self) -> None:
        self.calls: list[tuple[DependencyCoordinate, ...]] = []

    def query_batch(
        self, coordinates: Sequence[DependencyCoordinate]
    ) -> Mapping[DependencyCoordinate, tuple[OsvAdvisory, ...]]:
        batch = tuple(coordinates)
        self.calls.append(batch)
        return {
            coordinate: (_ADVISORY,)
            for coordinate in batch
            if (coordinate.ecosystem, coordinate.name, coordinate.version)
            == ("PyPI", "pipeline-fixture-pkg", "1.0.0")
        }


class _FixtureCweProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def ensure(self, cwe_ids: Sequence[str], *, deadline: float | None = None) -> CweEvidenceResult:
        del deadline
        selected = tuple(cwe_ids)
        self.calls.append(selected)
        return CweEvidenceResult({"CWE-95": _CWE_REF})


class _FixtureRetriever:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def search(self, query: str, limit: int = 5) -> tuple[DocumentChunk, ...]:
        self.calls.append((query, limit))
        return (_CHUNK,)


def _finding(identifier: str, path: str) -> Finding:
    return Finding(
        id=identifier,
        rule_id="FIXTURE/EVAL",
        category="sast",
        severity=Severity.HIGH,
        file_path=path,
        line_start=1,
        message="Synthetic evaluation finding.",
        redacted_evidence="[fixture source omitted]",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-95",),
        remediation="Use a safe parser.",
        engine="fixture_sast",
    )


def _fixture_scanner(request: ScanRequest) -> DeterministicScanResult:
    if request.target.name != "contract" or (request.target / "app.py").read_bytes() != _SOURCE:
        raise ValueError("invalid fixture source")
    return DeterministicScanResult(
        target_name=request.target_name or "contract",
        findings=(_finding("fixture-sast-1", "app.py"),),
        executions=(
            ScanExecution(
                engine="fixture_sast",
                kind="sast",
                status="completed",
                version="synthetic-v1",
                elapsed_ms=0,
                eligible_files=("app.py",),
                scanned_files=("app.py",),
                languages=("python",),
                checks=("FIXTURE/EVAL",),
            ),
        ),
    )


def _revision() -> tuple[str, bool]:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("git unavailable")

    def git(*args: str) -> str:
        result = subprocess.run(  # noqa: S603
            [executable, "-C", str(_ROOT), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            shell=False,  # nosec B603
        )
        if result.returncode:
            raise ValueError("source revision unavailable")
        return result.stdout.strip()

    revision = git("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is None:
        raise ValueError("source revision invalid")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    return revision, dirty


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _retrieval_reuse_contract() -> dict[str, int | bool]:
    retriever = _FixtureRetriever()
    findings = tuple(_finding(f"fixture-repeat-{index}", f"copy-{index}.py") for index in range(20))

    def scanner(request: ScanRequest) -> DeterministicScanResult:
        return DeterministicScanResult(
            target_name=request.target_name or "repeat-contract", findings=findings
        )

    with tempfile.TemporaryDirectory(prefix="secragraph-retrieval-contract-") as folder:
        target = Path(folder) / "inert.py"
        target.write_bytes(_SOURCE)
        report = ScanService(
            InMemoryReportRepository(),
            graph_services=ScanGraphServices(deterministic_scanner=scanner, retriever=retriever),
        ).scan(target, target_name="repeat-contract")
    all_cited = len(report.findings) == len(findings) and all(
        any(ref.id == _CHUNK.id for ref in finding.references) for finding in report.findings
    )
    _require(len(retriever.calls) == 1 and all_cited, "retrieval reuse contract failed")
    return {
        "identical_findings": len(findings),
        "observed_calls": len(retriever.calls),
        "all_cited": all_cited,
    }


def evaluate_contract() -> dict[str, object]:
    """Return only bounded metadata after graph, provider and persistence checks pass."""

    started = monotonic()
    queryer = _FixtureQueryer()
    cwe = _FixtureCweProvider()
    retriever = _FixtureRetriever()
    repository = InMemoryReportRepository()
    with tempfile.TemporaryDirectory(prefix="secragraph-provider-contract-") as folder:
        target = Path(folder) / "contract"
        target.mkdir()
        (target / "app.py").write_bytes(_SOURCE)
        (target / "uv.lock").write_bytes(_LOCK)
        service = ScanService(
            repository,
            graph_services=ScanGraphServices(
                deterministic_scanner=_fixture_scanner,
                dependency_auditor=LiveDependencyAuditor(queryer),
                cwe_evidence=cwe,
                retriever=retriever,
            ),
        )
        report = service.scan(target, target_name="contract", owner_member_id=_OWNER)
    stored = repository.get(report.scan_id, owner_member_id=_OWNER)
    by_engine = {finding.engine: finding for finding in report.findings}
    execution_by_engine = {execution.engine: execution for execution in report.executions}
    _require(stored == report, "report persistence contract failed")
    _require(report.status.value == "completed", "scan status incomplete")
    _require(set(by_engine) == {"fixture_sast", "osv"}, "finding engine contract failed")
    _require(len(queryer.calls) == 1, "OSV adapter call contract failed")
    coordinates = tuple(f"{item.ecosystem}:{item.name}:{item.version}" for item in queryer.calls[0])
    _require(coordinates == ("PyPI:pipeline-fixture-pkg:1.0.0",), "lockfile contract failed")
    _require(cwe.calls == [("CWE-95",)], "CWE adapter call contract failed")
    _require(len(retriever.calls) == 2, "RAG adapter call contract failed")
    _require(
        tuple(ref.id for ref in by_engine["fixture_sast"].references)
        == ("mitre:CWE-95", "fixture:guide:1"),
        "CWE and RAG citation contract failed",
    )
    _require(
        tuple(ref.id for ref in by_engine["osv"].references)
        == ("osv:OSV-TEST-0001", "fixture:guide:1"),
        "OSV and RAG provenance contract failed",
    )
    _require(
        execution_by_engine["osv"].status == "completed"
        and execution_by_engine["osv"].eligible_files == ("uv.lock",)
        and execution_by_engine["osv"].scanned_files == ("uv.lock",),
        "OSV execution coverage contract failed",
    )
    reuse = _retrieval_reuse_contract()
    revision, dirty = _revision()
    return {
        "schema_version": 1,
        "scope": "synthetic_adapter_contract",
        "source_revision": revision,
        "source_dirty": dirty,
        "fixture_sha256": sha256(_SOURCE + b"\0" + _LOCK, usedforsecurity=False).hexdigest(),
        "passed": True,
        "coverage": {"cases_passed": 1, "cases_total": 1},
        "providers": {
            "dependency_audit": {
                "calls": len(queryer.calls),
                "coordinates": list(coordinates),
            },
            "cwe": {"calls": len(cwe.calls), "requested_ids": list(cwe.calls[0])},
            "rag": {
                "calls": len(retriever.calls),
                "osv_finding_cited": any(
                    reference.id == _CHUNK.id for reference in by_engine["osv"].references
                ),
            },
        },
        "report": {
            "status": report.status.value,
            "finding_count": len(report.findings),
            "persisted": stored == report,
            "reference_ids_by_engine": {
                engine: [ref.id for ref in finding.references]
                for engine, finding in sorted(by_engine.items())
            },
            "executions": {
                engine: {
                    "status": execution.status,
                    "eligible_files": list(execution.eligible_files),
                    "scanned_files": list(execution.scanned_files),
                    "elapsed_ms": execution.elapsed_ms,
                }
                for engine, execution in sorted(execution_by_engine.items())
            },
        },
        "retrieval_calls": reuse,
        "elapsed_ms": max(0, round((monotonic() - started) * 1000)),
        "limitations": list(_LIMITATIONS),
    }


def _markdown(result: Mapping[str, object]) -> str:
    coverage = cast(dict[str, Any], result["coverage"])
    providers = cast(dict[str, Any], result["providers"])
    report = cast(dict[str, Any], result["report"])
    reuse = cast(dict[str, Any], result["retrieval_calls"])
    provider_calls = (
        f"dependency {providers['dependency_audit']['calls']}, "
        f"CWE {providers['cwe']['calls']}, RAG {providers['rag']['calls']}"
    )
    retrieval_summary = (
        f"Identical-query findings: {reuse['identical_findings']}; "
        f"retrieval calls: {reuse['observed_calls']}; all cited: {reuse['all_cited']}."
    )
    lines = [
        "# Controlled pipeline contract",
        "",
        "Scope: synthetic adapter contract; not live provider or detector accuracy.",
        f"Source revision: `{result['source_revision']}`; "
        f"dirty: `{str(result['source_dirty']).lower()}`.",
        f"Fixture SHA-256: `{result['fixture_sha256']}`.",
        f"Cases passed: {coverage['cases_passed']}/{coverage['cases_total']}.",
        f"Findings in persisted report: {report['finding_count']}.",
        f"Provider calls: {provider_calls}.",
        retrieval_summary,
        f"Elapsed: {result['elapsed_ms']} ms.",
        "",
        "## Limits",
        "",
        *[f"- {item}" for item in _LIMITATIONS],
        "",
    ]
    return "\n".join(lines)


def _write(output_dir: Path, result: Mapping[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "pipeline-contract.json": json.dumps(result, indent=2, sort_keys=True) + "\n",
        "pipeline-contract.md": _markdown(result),
    }
    pending: list[tuple[Path, Path]] = []
    try:
        for name, content in contents.items():
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=output_dir, delete=False
            ) as handle:
                handle.write(content)
                pending.append((Path(handle.name), output_dir / name))
        for temporary, destination in pending:
            os.replace(temporary, destination)
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=_ROOT / "build/evidence")
    args = parser.parse_args(argv)
    outputs = [args.output_dir / "pipeline-contract.json", args.output_dir / "pipeline-contract.md"]
    for output in outputs:
        output.unlink(missing_ok=True)
    try:
        result = evaluate_contract()
        _write(args.output_dir, result)
    except (OSError, RuntimeError, ValueError, AssertionError):
        for output in outputs:
            output.unlink(missing_ok=True)
        print("Controlled pipeline contract failed.", file=sys.stderr)
        return 1
    print("Controlled pipeline contract passed (1/1 synthetic adapter case).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
