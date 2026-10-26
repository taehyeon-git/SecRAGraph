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

    def save(self, report: ScanReport, *, owner_member_id: UUID | None = None) -> None:
        row = ScanReportRow.from_domain(report)
        row.owner_member_id = owner_member_id
        try:
            with self._session_factory.begin() as session:
                session.add(row)
        except SQLAlchemyError as error:
            raise ReportRepositoryError("report persistence failed") from error

    def get(self, scan_id: UUID, *, owner_member_id: UUID | None = None) -> ScanReport | None:
        statement = (
            select(ScanReportRow)
            .where(ScanReportRow.scan_id == scan_id)
            .options(selectinload(ScanReportRow.findings))
        )
        if owner_member_id is not None:
            statement = statement.where(ScanReportRow.owner_member_id == owner_member_id)
        try:
            with self._session_factory() as session:
                row = session.scalar(statement)
                return None if row is None else row.to_domain()
        except SQLAlchemyError as error:
            raise ReportRepositoryError("report retrieval failed") from error
