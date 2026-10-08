"""Transactional append-only PostgreSQL audit sink."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from security_review.audit import AuditEvent
from security_review.storage.models import AuditEventRow


class PostgresAuditSink:
    """Store only fields already validated by AuditEvent."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def record(self, event: AuditEvent) -> None:
        with self._sessions.begin() as session:
            session.add(
                AuditEventRow(
                    scan_id=UUID(event.scan_id) if event.scan_id is not None else None,
                    correlation_id=UUID(event.correlation_id),
                    event_type=event.event_type,
                    details=dict(event.attributes),
                )
            )
