from __future__ import annotations

from uuid import UUID

from security_review.domain.models import (
    Confidence,
    Finding,
    ScanReport,
    Severity,
    SourceReference,
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
    identifier: str = "SEC001:stable",
    *,
    path: str = "src/settings.py",
    line: int = 7,
) -> Finding:
    return Finding(
        id=identifier,
        rule_id="SEC001",
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
            sample_finding("SEC001:later", path="z.py", line=9),
            sample_finding("SEC001:earlier", path="a.py", line=2),
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
        "SEC001:earlier",
        "SEC001:later",
    ]
    assert row.summary == report.summary.model_dump(mode="json")
    assert row.risk == report.risk.model_dump(mode="json")
