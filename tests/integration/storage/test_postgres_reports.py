from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from security_review.domain.models import Confidence, Finding, Severity
from security_review.ports import ReportRepositoryError
from security_review.reporting.builder import build_report
from security_review.storage.database import create_session_factory
from security_review.storage.reports import SqlAlchemyReportRepository

pytestmark = pytest.mark.integration


def database_url() -> str:
    return os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@localhost:55432/secragraph_test",
    )


def sample_finding() -> Finding:
    return Finding(
        id="PY001:stable",
        rule_id="PY001",
        category="code_pattern",
        severity=Severity.HIGH,
        file_path="src/app.py",
        line_start=4,
        message="Dynamic evaluation detected.",
        redacted_evidence="eval(user_input)",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-95",),
        remediation="Use an explicit parser.",
    )


@pytest.fixture(scope="session")
def session_factory() -> sessionmaker[Session]:
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", database_url())
    command.upgrade(configuration, "head")
    return create_session_factory(database_url())


@pytest.fixture(autouse=True)
def clean_database(session_factory: sessionmaker[Session]) -> Iterator[None]:
    with session_factory.begin() as session:
        session.execute(
            text(
                "TRUNCATE app.audit_events, app.findings, app.scan_reports RESTART IDENTITY CASCADE"
            )
        )
    yield


def test_postgres_repository_round_trips_canonical_report(
    session_factory: sessionmaker[Session],
) -> None:
    report = build_report("app.py", [sample_finding()])
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)

    assert repository.get(report.scan_id) == report


def test_child_constraint_failure_rolls_back_parent_report(
    session_factory: sessionmaker[Session],
) -> None:
    finding = sample_finding()
    report = build_report("app.py", [finding])
    invalid = report.model_copy(update={"findings": (finding, finding)})
    repository = SqlAlchemyReportRepository(session_factory)

    with pytest.raises(ReportRepositoryError) as captured:
        repository.save(invalid)

    assert isinstance(captured.value.__cause__, IntegrityError)
    assert repository.get(report.scan_id) is None
