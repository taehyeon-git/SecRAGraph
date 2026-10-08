"""Transactional SQLAlchemy report repository."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload, sessionmaker

from security_review.domain.models import ScanReport
from security_review.ports import ReportRepositoryError
from security_review.storage.models import ScanReportRow


class SqlAlchemyReportRepository:
    """Persist a report and every finding in one database transaction."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save(self, report: ScanReport) -> None:
        row = ScanReportRow.from_domain(report)
        try:
            with self._session_factory.begin() as session:
                session.add(row)
        except SQLAlchemyError as error:
            raise ReportRepositoryError("report persistence failed") from error

    def get(self, scan_id: UUID) -> ScanReport | None:
        statement = (
            select(ScanReportRow)
            .where(ScanReportRow.scan_id == scan_id)
            .options(selectinload(ScanReportRow.findings))
        )
        try:
            with self._session_factory() as session:
                row = session.scalar(statement)
                return None if row is None else row.to_domain()
        except SQLAlchemyError as error:
            raise ReportRepositoryError("report retrieval failed") from error
