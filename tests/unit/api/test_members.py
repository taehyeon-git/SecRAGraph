from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.membership.service import MembershipError

MEMBER_ID = UUID("00000000-0000-0000-0000-000000000123")


@dataclass(frozen=True)
class FakeIdentity:
    user_id: UUID = MEMBER_ID
    username: str = "alice"


@dataclass(frozen=True)
class FakeLogin:
    token: str
    identity: FakeIdentity
    expires_at: datetime


class FakeMembership:
    def __init__(self) -> None:
        self.registered = False
        self.revoked = False
        self.fail_resolve = False

    def register(self, username: str, password: str) -> FakeIdentity:
        assert username == "alice" and password == "secure-password-123"
        self.registered = True
        return FakeIdentity()

    def login(self, username: str, password: str) -> FakeLogin:
        if username != "alice" or password != "secure-password-123":
            raise MembershipError("invalid_credentials")
        return FakeLogin(
            "member-secret",
            FakeIdentity(),
            datetime.now(UTC) + timedelta(hours=8),
        )

    def resolve(self, token: str) -> FakeIdentity | None:
        if token != "member-secret" or self.fail_resolve or self.revoked:
            return None
        return FakeIdentity()

    def logout(self, token: str) -> None:
        assert token == "member-secret"
        self.revoked = True


def _app(membership: FakeMembership, **settings: object):
    return create_app(
        Settings(environment="production", testing=True, **settings),
        membership=membership,
    )


def test_login_requires_no_operator_key_and_returns_no_store() -> None:
    membership = FakeMembership()
    with TestClient(_app(membership)) as client:
        unauthorized = client.get("/v1/auth/me")
        login = client.post(
            "/v1/auth/login",
            json={"username": "alice", "password": "secure-password-123"},
        )
        me = client.get("/v1/auth/me", headers={"Authorization": "Session member-secret"})
    assert unauthorized.status_code == 401
    assert login.status_code == 200
    assert login.json()["token"] == "member-secret"
    assert login.headers["cache-control"] == "no-store"
    assert me.json() == {"user_id": str(MEMBER_ID), "username": "alice"}


def test_bad_login_is_generic_and_registration_is_opt_in() -> None:
    membership = FakeMembership()
    with TestClient(_app(membership)) as client:
        wrong = client.post("/v1/auth/login", json={"username": "alice", "password": "wrong"})
        missing = client.post("/v1/auth/login", json={"username": "missing", "password": "wrong"})
        register = client.post(
            "/v1/auth/register",
            json={"username": "alice", "password": "secure-password-123"},
        )
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json()["code"] == missing.json()["code"] == "invalid_credentials"
    assert register.status_code == 403
    assert not membership.registered


def test_registration_only_in_explicit_development_mode() -> None:
    membership = FakeMembership()
    app = create_app(
        Settings(environment="development", testing=True, allow_self_registration=True),
        membership=membership,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/auth/register",
            json={"username": "alice", "password": "secure-password-123"},
        )
    assert response.status_code == 201
    assert membership.registered


def test_member_gate_rejects_duplicate_headers_and_invalid_sessions_before_body() -> None:
    membership = FakeMembership()
    with TestClient(_app(membership, max_request_bytes=10)) as client:
        duplicate = client.post(
            "/v1/scans/file",
            content=b"x" * 100,
            headers=[
                ("Authorization", "Session member-secret"),
                ("Authorization", "Session member-secret"),
            ],
        )
        expired = client.post(
            "/v1/scans/file",
            content=b"x" * 100,
            headers={"Authorization": "Session invalid"},
        )
    assert duplicate.status_code == expired.status_code == 401


def test_operator_and_member_credentials_are_distinct() -> None:
    membership = FakeMembership()
    with TestClient(_app(membership, api_token=SecretStr("operator-secret"))) as client:
        operator = client.get("/v1/auth/me", headers={"Authorization": "Bearer operator-secret"})
        wrong_kind = client.get("/v1/auth/me", headers={"Authorization": "Bearer member-secret"})
        member = client.get("/v1/auth/me", headers={"Authorization": "Session member-secret"})
    assert operator.status_code == wrong_kind.status_code == 401
    assert member.status_code == 200


def test_logout_revokes_session() -> None:
    membership = FakeMembership()
    with TestClient(_app(membership)) as client:
        logout = client.post("/v1/auth/logout", headers={"Authorization": "Session member-secret"})
        me = client.get("/v1/auth/me", headers={"Authorization": "Session member-secret"})
    assert logout.status_code == 204
    assert me.status_code == 401
