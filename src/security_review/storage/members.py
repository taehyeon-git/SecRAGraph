"""SQLAlchemy persistence adapter for membership accounts and sessions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from security_review.membership.service import (
    LOCKOUT_DURATION,
    MAX_FAILED_ATTEMPTS,
    SESSION_IDLE_LIFETIME,
    MemberRecord,
)
from security_review.storage.models import MemberRow, MemberSessionRow


class SqlAlchemyMembershipRepository:
    """Persist member state while serializing each account's login outcome."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    def create_member(self, username: str, password_hash: str) -> MemberRecord:
        row = MemberRow(user_id=uuid4(), username=username, password_hash=password_hash)
        try:
            with self.session_factory.begin() as session:
                session.add(row)
                session.flush()
                session.expunge(row)
        except IntegrityError:
            raise ValueError("username already exists") from None
        return _record(row)

    def authenticate(
        self,
        username: str,
        password: str,
        verifier: Callable[[str, str], bool | None],
        dummy_verifier: str,
        now: datetime,
        session_digest: str,
        expires_at: datetime,
    ) -> MemberRecord | None:
        with self.session_factory.begin() as session:
            row = session.scalar(
                select(MemberRow).where(MemberRow.username == username).with_for_update()
            )
            encoded = row.password_hash if row is not None else dummy_verifier
            valid = verifier(password, encoded)
            if valid is None:
                return None
            if row is None or row.disabled:
                return None
            if row.locked_until is not None and now < _aware(row.locked_until):
                return None
            if not valid:
                row.failed_attempts += 1
                if row.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    row.locked_until = now + LOCKOUT_DURATION
                return None
            row.failed_attempts = 0
            row.locked_until = None
            session.add(
                MemberSessionRow(
                    token_digest=session_digest,
                    member_id=row.user_id,
                    created_at=now,
                    last_seen_at=now,
                    expires_at=expires_at,
                )
            )
            session.flush()
            return _record(row)

    def resolve_session(self, session_digest: str, now: datetime) -> MemberRecord | None:
        with self.session_factory.begin() as session:
            member_id = session.scalar(
                select(MemberSessionRow.member_id).where(
                    MemberSessionRow.token_digest == session_digest
                )
            )
            if member_id is None:
                return None
            # Always lock accounts before their sessions. disable_member follows
            # this order and deletes sessions after locking the member row.
            member = session.scalar(
                select(MemberRow).where(MemberRow.user_id == member_id).with_for_update()
            )
            session_row = session.scalar(
                select(MemberSessionRow)
                .where(MemberSessionRow.token_digest == session_digest)
                .with_for_update()
            )
            if session_row is None:
                return None
            if (
                now >= _aware(session_row.expires_at)
                or now - _aware(session_row.last_seen_at) >= SESSION_IDLE_LIFETIME
            ):
                session.delete(session_row)
                return None
            if member is None or member.disabled:
                session.delete(session_row)
                return None
            session_row.last_seen_at = now
            session.flush()
            return _record(member)

    def revoke_session(self, session_digest: str) -> None:
        with self.session_factory.begin() as session:
            session.execute(
                delete(MemberSessionRow).where(MemberSessionRow.token_digest == session_digest)
            )

    def disable_member(self, username: str) -> bool:
        with self.session_factory.begin() as session:
            row = session.scalar(
                select(MemberRow).where(MemberRow.username == username).with_for_update()
            )
            if row is None:
                return False
            row.disabled = True
            session.execute(
                delete(MemberSessionRow).where(MemberSessionRow.member_id == row.user_id)
            )
            return True

    def unlock_member(self, username: str) -> bool:
        with self.session_factory.begin() as session:
            row = session.scalar(
                select(MemberRow).where(MemberRow.username == username).with_for_update()
            )
            if row is None:
                return False
            row.failed_attempts = 0
            row.locked_until = None
            return True


def _record(row: MemberRow) -> MemberRecord:
    return MemberRecord(
        row.user_id,
        row.username,
        row.password_hash,
        row.disabled,
        row.failed_attempts,
        row.locked_until,
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
