"""Round-trip every safe event type through the append-only audit table."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from security_review.audit import AuditEvent
from security_review.storage.audit import PostgresAuditSink
from security_review.storage.database import create_session_factory
from security_review.storage.models import AuditEventRow

pytestmark = pytest.mark.integration


@pytest.fixture
def sessions() -> sessionmaker[Session]:
    url = os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@localhost:55432/secragraph_test",
    )
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", url)
    command.upgrade(configuration, "head")
    factory = create_session_factory(url)
    with factory.begin() as session:
        session.execute(text("TRUNCATE app.audit_events RESTART IDENTITY"))
    return factory


def test_every_event_type_round_trips_with_safe_attributes(sessions: sessionmaker[Session]) -> None:
    correlation_id = str(uuid4())
    sink = PostgresAuditSink(sessions)
    events = [
        AuditEvent(event_type="scan_started", correlation_id=correlation_id),
        AuditEvent(
            event_type="scan_completed",
            correlation_id=correlation_id,
            attributes={"finding_count": 2, "high_count": 1},
        ),
        AuditEvent(
            event_type="route_selected",
            correlation_id=correlation_id,
            attributes={"route": "rag"},
        ),
        AuditEvent(
            event_type="retry_performed",
            correlation_id=correlation_id,
            attributes={"route": "rag", "attempt": 2},
        ),
        AuditEvent(
            event_type="dependency_failed",
            correlation_id=correlation_id,
            attributes={"dependency": "qdrant", "reason": "unavailable"},
        ),
    ]

    for event in events:
        sink.record(event)

    with sessions() as session:
        rows = session.scalars(select(AuditEventRow).order_by(AuditEventRow.event_id)).all()
    assert [row.event_type for row in rows] == [event.event_type for event in events]
    assert all(str(row.correlation_id) == correlation_id for row in rows)
    assert [row.details for row in rows] == [event.attributes for event in events]
    assert all(row.created_at is not None for row in rows)
    blocked = {"source", "content", "prompt", "token", "password", "secret"}
    assert all(not blocked.intersection(key.lower() for key in row.details) for row in rows)
