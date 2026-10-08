"""Normalized PostgreSQL rows and canonical domain mappers."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    MetaData,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from security_review.domain.models import Finding, ScanReport

_NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for the isolated application schema."""

    metadata = MetaData(schema="app", naming_convention=_NAMING_CONVENTION)


class ScanReportRow(Base):
    """One canonical scan report with normalized child findings."""

    __tablename__ = "scan_reports"

    scan_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    target_name: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    warnings: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="report",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    @classmethod
    def from_domain(cls, report: ScanReport) -> ScanReportRow:
        row = cls(
            scan_id=report.scan_id,
            created_at=report.created_at,
            status=report.status.value,
            target_name=report.target_name,
            summary=report.summary.model_dump(mode="json"),
            risk=report.risk.model_dump(mode="json"),
            warnings=list(report.warnings),
            tool_version=report.tool_version,
            rule_set_version=report.rule_set_version,
        )
        row.findings = [FindingRow.from_domain(report.scan_id, item) for item in report.findings]
        return row

    def to_domain(self) -> ScanReport:
        ordered = sorted(
            (item.to_domain() for item in self.findings),
            key=lambda item: (item.file_path, item.line_start, item.rule_id, item.id),
        )
        return ScanReport.model_validate(
            {
                "scan_id": self.scan_id,
                "created_at": self.created_at,
                "status": self.status,
                "target_name": self.target_name,
                "summary": self.summary,
                "risk": self.risk,
                "findings": ordered,
                "warnings": self.warnings,
                "tool_version": self.tool_version,
                "rule_set_version": self.rule_set_version,
            }
        )


class FindingRow(Base):
    """One normalized finding belonging to a scan report."""

    __tablename__ = "findings"
    scan_id: Mapped[UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("app.scan_reports.scan_id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_start: Mapped[int] = mapped_column(nullable=False)
    line_end: Mapped[int | None] = mapped_column(nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    redacted_evidence: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    report: Mapped[ScanReportRow] = relationship(back_populates="findings")

    @classmethod
    def from_domain(cls, scan_id: UUID, finding: Finding) -> FindingRow:
        return cls(
            scan_id=scan_id,
            finding_id=finding.id,
            rule_id=finding.rule_id,
            category=finding.category,
            severity=finding.severity.value,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            message=finding.message,
            redacted_evidence=finding.redacted_evidence,
            confidence=finding.confidence.value,
            cwe_ids=list(finding.cwe_ids),
            remediation=finding.remediation,
            references=[item.model_dump(mode="json") for item in finding.references],
        )

    def to_domain(self) -> Finding:
        return Finding.model_validate(
            {
                "id": self.finding_id,
                "rule_id": self.rule_id,
                "category": self.category,
                "severity": self.severity,
                "file_path": self.file_path,
                "line_start": self.line_start,
                "line_end": self.line_end,
                "message": self.message,
                "redacted_evidence": self.redacted_evidence,
                "confidence": self.confidence,
                "cwe_ids": self.cwe_ids,
                "remediation": self.remediation,
                "references": self.references,
            }
        )


class AuditEventRow(Base):
    """Append-only operational event reserved for lifecycle auditing."""

    __tablename__ = "audit_events"

    event_id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    correlation_id: Mapped[UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)
    scan_id: Mapped[UUID | None] = mapped_column(
        PostgreSQLUUID(as_uuid=True),
        ForeignKey("app.scan_reports.scan_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
