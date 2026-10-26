"""Membership rules and repository protocol."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Protocol
from uuid import UUID, uuid4

from security_review.membership.passwords import hash_password, verify_password

SESSION_ABSOLUTE_LIFETIME = timedelta(hours=8)
SESSION_IDLE_LIFETIME = timedelta(minutes=30)
LOCKOUT_DURATION = timedelta(minutes=15)
MAX_FAILED_ATTEMPTS = 5
_USERNAME_RE = re.compile(r"^[\x21-\x7e]{3,32}$")
_DUMMY_VERIFIER = (
    "scrypt$1$32768$8$3$WiEFIRCLMs3ahqOWjN8Cfw$WVfNroCFovA32EiIwNi52-ODD1jNCF8G4paGISOdNng"
)


@dataclass(frozen=True, slots=True)
class MemberIdentity:
    user_id: UUID
    username: str


@dataclass(frozen=True, slots=True)
class LoginResult:
    token: str = field(repr=False)
    identity: MemberIdentity
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MemberRecord:
    user_id: UUID
    username: str
    password_hash: str = field(repr=False)
    disabled: bool
    failed_attempts: int
    locked_until: datetime | None

    @property
    def identity(self) -> MemberIdentity:
        return MemberIdentity(self.user_id, self.username)


class MembershipError(Exception):
    """A bounded, safe membership error code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MembershipRepository(Protocol):
    def create_member(self, username: str, password_hash: str) -> MemberRecord: ...

    def authenticate(
        self,
        username: str,
        password: str,
        verifier: Callable[[str, str], bool | None],
        dummy_verifier: str,
        now: datetime,
        session_digest: str,
        expires_at: datetime,
    ) -> MemberRecord | None: ...

    def resolve_session(self, session_digest: str, now: datetime) -> MemberRecord | None: ...

    def revoke_session(self, session_digest: str) -> None: ...

    def disable_member(self, username: str) -> bool: ...

    def unlock_member(self, username: str) -> bool: ...


def normalize_username(username: str) -> str:
    """Trim and lowercase an ASCII username, rejecting invalid characters/length."""

    normalized = username.strip().lower() if isinstance(username, str) else ""
    if not _USERNAME_RE.fullmatch(normalized) or not normalized.isascii():
        raise MembershipError("invalid_input")
    return normalized


def session_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class MembershipService:
    def __init__(self, repository: MembershipRepository) -> None:
        self.repository = repository

    def register(self, username: str, password: str) -> MemberIdentity:
        normalized = normalize_username(username)
        try:
            encoded = hash_password(password)
        except (ValueError, TypeError):
            raise MembershipError("invalid_input") from None
        try:
            return self.repository.create_member(normalized, encoded).identity
        except ValueError:
            raise MembershipError("username_taken") from None

    def login(self, username: str, password: str, now: datetime | None = None) -> LoginResult:
        instant = _utc(now)
        normalized = username.strip().lower() if isinstance(username, str) else ""
        password_is_valid = False
        if isinstance(password, str) and len(password) <= 1024:
            try:
                password_is_valid = 12 <= len(password.encode("utf-8")) <= 1024
            except UnicodeEncodeError:
                pass
        password_for_verification = password if password_is_valid else "bounded invalid password"

        def verify_bounded(candidate: str, encoded: str) -> bool | None:
            verified = verify_password(candidate, encoded)
            return verified if password_is_valid else None

        token = secrets.token_urlsafe(32)
        expires_at = instant + SESSION_ABSOLUTE_LIFETIME
        try:
            record = self.repository.authenticate(
                normalized,
                password_for_verification,
                verify_bounded,
                _DUMMY_VERIFIER,
                instant,
                session_digest(token),
                expires_at,
            )
        except (ValueError, TypeError):
            record = None
        if record is None:
            raise MembershipError("invalid_credentials")
        return LoginResult(token, record.identity, expires_at)

    def resolve(self, token: str, now: datetime | None = None) -> MemberIdentity | None:
        if not isinstance(token, str) or not token:
            return None
        record = self.repository.resolve_session(session_digest(token), _utc(now))
        return record.identity if record is not None else None

    def logout(self, token: str) -> None:
        if isinstance(token, str) and token:
            self.repository.revoke_session(session_digest(token))

    def disable(self, username: str) -> None:
        normalized = normalize_username(username)
        if not self.repository.disable_member(normalized):
            raise MembershipError("not_found")

    def unlock(self, username: str) -> None:
        normalized = normalize_username(username)
        if not self.repository.unlock_member(normalized):
            raise MembershipError("not_found")


@dataclass(slots=True)
class _InMemoryMember:
    user_id: UUID
    username: str
    password_hash: str
    disabled: bool = False
    failed_attempts: int = 0
    locked_until: datetime | None = None

    def record(self) -> MemberRecord:
        return MemberRecord(
            self.user_id,
            self.username,
            self.password_hash,
            self.disabled,
            self.failed_attempts,
            self.locked_until,
        )


@dataclass(slots=True)
class _InMemorySession:
    user_id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime


class InMemoryMembershipRepository:
    """Thread-safe test repository implementing account and session policy."""

    def __init__(self) -> None:
        self._members: dict[str, _InMemoryMember] = {}
        self._sessions: dict[str, _InMemorySession] = {}
        self._lock = RLock()

    def create_member(self, username: str, password_hash: str) -> MemberRecord:
        with self._lock:
            if username in self._members:
                raise ValueError("username already exists")
            member = _InMemoryMember(uuid4(), username, password_hash)
            self._members[username] = member
            return member.record()

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
        with self._lock:
            member = self._members.get(username)
            encoded = member.password_hash if member is not None else dummy_verifier
            valid = verifier(password, encoded)
            if valid is None:
                return None
            if member is None or member.disabled:
                return None
            if member.locked_until is not None and now < member.locked_until:
                return None
            if not valid:
                member.failed_attempts += 1
                if member.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    member.locked_until = now + LOCKOUT_DURATION
                return None
            member.failed_attempts = 0
            member.locked_until = None
            self._sessions[session_digest] = _InMemorySession(member.user_id, now, now, expires_at)
            return member.record()

    def resolve_session(self, session_digest: str, now: datetime) -> MemberRecord | None:
        with self._lock:
            session = self._sessions.get(session_digest)
            if session is None:
                return None
            if now >= session.expires_at or now - session.last_seen_at >= SESSION_IDLE_LIFETIME:
                del self._sessions[session_digest]
                return None
            member = next(
                (item for item in self._members.values() if item.user_id == session.user_id), None
            )
            if member is None or member.disabled:
                del self._sessions[session_digest]
                return None
            session.last_seen_at = now
            return member.record()

    def revoke_session(self, session_digest: str) -> None:
        with self._lock:
            self._sessions.pop(session_digest, None)

    def disable_member(self, username: str) -> bool:
        with self._lock:
            member = self._members.get(username)
            if member is None:
                return False
            member.disabled = True
            for digest, session in list(self._sessions.items()):
                if session.user_id == member.user_id:
                    del self._sessions[digest]
            return True

    def unlock_member(self, username: str) -> bool:
        with self._lock:
            member = self._members.get(username)
            if member is None:
                return False
            member.failed_attempts = 0
            member.locked_until = None
            return True


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        raise MembershipError("invalid_input")
    return value.astimezone(UTC)
