import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, delete, event, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from security_review.membership.passwords import hash_password, verify_password
from security_review.membership.service import session_digest
from security_review.storage.database import create_session_factory
from security_review.storage.members import SqlAlchemyMembershipRepository
from security_review.storage.models import MemberRow, MemberSessionRow, ScanReportRow

pytestmark = pytest.mark.integration


@pytest.fixture
def repository() -> Iterator[tuple[SqlAlchemyMembershipRepository, sessionmaker[Session]]]:
    database_url = os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@127.0.0.1:55432/secragraph_test",
    )
    probe = create_engine(database_url, connect_args={"connect_timeout": 2})
    try:
        with probe.connect():
            pass
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL test database is unavailable: {exc.__class__.__name__}")
    finally:
        probe.dispose()
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(configuration, "head")
    factory = create_session_factory(database_url)
    yield SqlAlchemyMembershipRepository(factory), factory


def test_concurrent_failed_logins_enforce_exact_lockout_and_persist_only_digest(repository):
    repo, factory = repository
    username = f"race-{uuid4().hex[:12]}"
    repo.create_member(username, hash_password("a sufficiently long password"))
    now = datetime.now(UTC)

    def wrong_login(index: int) -> None:
        repo.authenticate(
            username,
            "not the password",
            verify_password,
            "bad verifier",
            now,
            f"{uuid4().hex}{index:02d}",
            now + timedelta(hours=8),
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(wrong_login, range(5)))

    with factory() as session:
        member = session.scalar(select(MemberRow).where(MemberRow.username == username))
        assert member is not None
        assert member.failed_attempts == 5
        assert member.locked_until == now + timedelta(minutes=15)
        sessions = session.scalars(
            select(MemberSessionRow).where(MemberSessionRow.member_id == member.user_id)
        ).all()
        assert sessions == []


def test_database_repository_stores_digest_and_enforces_disabled_and_expired_session(repository):
    repo, factory = repository
    username = f"session-{uuid4().hex[:12]}"
    repo.create_member(username, hash_password("a sufficiently long password"))
    with pytest.raises(ValueError):
        repo.create_member(username, hash_password("a sufficiently long password"))
    now = datetime.now(UTC)
    raw_token = "a one-time session token"
    digest = session_digest(raw_token)
    record = repo.authenticate(
        username,
        "a sufficiently long password",
        verify_password,
        "bad verifier",
        now,
        digest,
        now + timedelta(hours=8),
    )
    assert record is not None
    with factory() as session:
        stored = session.get(MemberSessionRow, digest)
        assert stored is not None
        assert raw_token not in stored.token_digest

    assert repo.resolve_session(digest, now + timedelta(minutes=29)) is not None
    assert repo.resolve_session(digest, now + timedelta(minutes=60)) is None
    absolute_digest = session_digest("another one-time token")
    assert (
        repo.authenticate(
            username,
            "a sufficiently long password",
            verify_password,
            "bad verifier",
            now,
            absolute_digest,
            now + timedelta(hours=8),
        )
        is not None
    )
    assert repo.resolve_session(absolute_digest, now + timedelta(hours=8)) is None
    assert repo.disable_member(username)
    assert (
        repo.authenticate(
            username,
            "a sufficiently long password",
            verify_password,
            "bad verifier",
            now,
            f"{uuid4().hex}",
            now + timedelta(hours=8),
        )
        is None
    )


def test_membership_migration_preserves_existing_unowned_report(repository):
    _, factory = repository
    report_id = uuid4()
    created_at = datetime.now(UTC)
    with factory.begin() as session:
        session.add(
            ScanReportRow(
                scan_id=report_id,
                created_at=created_at,
                status="completed",
                target_name="legacy-report.zip",
                summary={"finding_count": 0},
                risk={"score": 0},
                warnings=[],
                tool_version="test",
                rule_set_version="test",
                findings=[],
            )
        )

    database_url = os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@127.0.0.1:55432/secragraph_test",
    )
    configuration = Config("alembic.ini")
    configuration.set_main_option("sqlalchemy.url", database_url)
    command.downgrade(configuration, "20261018_0004")
    command.upgrade(configuration, "head")

    with factory() as session:
        restored = session.get(ScanReportRow, report_id)
        assert restored is not None
        assert restored.target_name == "legacy-report.zip"
        assert restored.owner_member_id is None


def test_disable_committing_during_session_resolution_fails_closed(repository):
    repo, factory = repository
    username = f"disable-{uuid4().hex[:12]}"
    member = repo.create_member(username, hash_password("a sufficiently long password"))
    now = datetime.now(UTC)
    digest = session_digest(uuid4().hex)
    assert (
        repo.authenticate(
            username,
            "a sufficiently long password",
            verify_password,
            "bad verifier",
            now,
            digest,
            now + timedelta(hours=8),
        )
        is not None
    )
    lookup_started = Event()
    engine = factory.kw["bind"]

    def observe_session_lookup(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().upper().startswith("SELECT") and "app.member_sessions" in statement:
            lookup_started.set()

    event.listen(engine, "before_cursor_execute", observe_session_lookup)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with factory.begin() as disabling_session:
                disabling_session.scalar(
                    select(MemberRow).where(MemberRow.user_id == member.user_id).with_for_update()
                )
                resolving = pool.submit(repo.resolve_session, digest, now + timedelta(seconds=1))
                assert lookup_started.wait(timeout=5)
                disabling_session.execute(
                    delete(MemberSessionRow).where(MemberSessionRow.member_id == member.user_id)
                )
                disabling_session.execute(
                    update(MemberRow)
                    .where(MemberRow.user_id == member.user_id)
                    .values(disabled=True)
                )
            assert resolving.result(timeout=5) is None
    finally:
        event.remove(engine, "before_cursor_execute", observe_session_lookup)
