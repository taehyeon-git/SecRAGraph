from __future__ import annotations

from uuid import UUID, uuid4

from security_review.domain.models import (
    Confidence,
    Finding,
    ScanExecution,
    ScanReport,
    Severity,
    SourceReference,
    TraceLocation,
)
from security_review.ports import ReportRepository
from security_review.reporting.builder import build_report
from security_review.storage.memory import InMemoryReportRepository
from security_review.storage.models import FindingRow, ScanReportRow


class FakeReportRepository:
    def __init__(self) -> None:
        self.reports: dict[UUID, ScanReport] = {}

    def save(self, report: ScanReport) -> None:
        self.reports[report.scan_id] = report

    def get(self, scan_id: UUID) -> ScanReport | None:
        return self.reports.get(scan_id)


def sample_finding(
    identifier: str = "GITLEAKS:stable",
    *,
    path: str = "src/settings.py",
    line: int = 7,
) -> Finding:
    return Finding(
        id=identifier,
        rule_id="GITLEAKS/generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        file_path=path,
        line_start=line,
        line_end=line,
        message="Secret-like value detected.",
        redacted_evidence="OPENAI_API_KEY = ***REDACTED***",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-798",),
        remediation="Load the replacement from a secret store.",
        engine="gitleaks",
        references=(
            SourceReference(
                id="owasp-secrets",
                title="OWASP Secrets Management",
                source_url="https://owasp.org/example",
                section="Rotation",
                score=0.91,
            ),
        ),
    )


def sample_report() -> ScanReport:
    return build_report(
        "portfolio.zip",
        [
            sample_finding("GITLEAKS:later", path="z.py", line=9),
            sample_finding("GITLEAKS:earlier", path="a.py", line=2),
        ],
        ["ignored.bin:unsupported_extension"],
    )


def repository_contract(repository: ReportRepository, report: ScanReport) -> None:
    repository.save(report)
    assert repository.get(report.scan_id) == report


def test_repository_protocol_accepts_an_in_memory_fake() -> None:
    repository_contract(FakeReportRepository(), sample_report())


def test_in_memory_adapter_obeys_repository_contract() -> None:
    repository_contract(InMemoryReportRepository(), sample_report())


def test_in_memory_report_ownership_is_isolated_from_other_members() -> None:
    repository = InMemoryReportRepository()
    owner = uuid4()
    other = uuid4()
    report = sample_report()
    legacy = sample_report().model_copy(update={"scan_id": uuid4()})

    repository.save(report, owner_member_id=owner)
    repository.save(legacy)

    assert repository.get(report.scan_id, owner_member_id=owner) == report
    assert repository.get(report.scan_id, owner_member_id=other) is None
    assert repository.get(legacy.scan_id, owner_member_id=owner) is None
    assert repository.get(report.scan_id) == report
    assert repository.get(legacy.scan_id) == legacy


def test_finding_row_round_trips_every_canonical_field() -> None:
    finding = sample_finding()

    row = FindingRow.from_domain(UUID("00000000-0000-0000-0000-000000000001"), finding)

    assert row.to_domain() == finding
    assert row.cwe_ids == ["CWE-798"]
    assert row.references[0]["id"] == "owasp-secrets"


def test_report_row_round_trips_json_fields_and_orders_findings() -> None:
    report = sample_report()

    row = ScanReportRow.from_domain(report)
    row.findings = list(reversed(row.findings))
    restored = row.to_domain()

    assert restored == report
    assert [finding.id for finding in restored.findings] == [
        "GITLEAKS:earlier",
        "GITLEAKS:later",
    ]
    assert row.summary == report.summary.model_dump(mode="json")
    assert row.risk == report.risk.model_dump(mode="json")


def test_report_row_round_trips_engine_coverage_and_source_free_trace() -> None:
    execution = ScanExecution(
        engine="opengrep",
        kind="sast",
        status="partial",
        version="1.32.0",
        elapsed_ms=42,
        eligible_files=("src/app.py",),
        scanned_files=("src/app.py",),
        languages=("python",),
        checks=("OG/taint",),
        reason="scan_partial",
    )
    source = TraceLocation(file_path="src/route.py", line_start=2, role="source")
    sink = TraceLocation(file_path="src/app.py", line_start=7, role="sink")
    finding = sample_finding(path="src/app.py").model_copy(
        update={"engine": "opengrep", "trace": (source, sink)}
    )
    report = build_report("repo", [finding], executions=(execution,))

    restored = ScanReportRow.from_domain(report).to_domain()

    assert restored == report
    assert restored.findings[0].trace == (source, sink)
    assert restored.executions == (execution,)
