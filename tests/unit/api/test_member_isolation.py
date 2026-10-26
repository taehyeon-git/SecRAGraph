"""A logged-in member cannot retrieve another member's persisted report."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import SecretStr

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.membership.service import InMemoryMembershipRepository, MembershipService
from security_review.storage.memory import InMemoryReportRepository


def _login(client: TestClient, username: str) -> str:
    response = client.post(
        "/v1/auth/login",
        json={"username": username, "password": "secure-password-123"},
    )
    assert response.status_code == 200
    return response.json()["token"]


def test_member_report_ownership_covers_all_formats_and_legacy_rows() -> None:
    membership = MembershipService(InMemoryMembershipRepository())
    membership.register("alice", "secure-password-123")
    membership.register("bob", "secure-password-123")
    reports = InMemoryReportRepository()
    app = create_app(
        Settings(environment="production", testing=True, api_token=SecretStr("operator-secret")),
        reports=reports,
        membership=membership,
    )
    with TestClient(app) as client:
        alice = {"Authorization": f"Session {_login(client, 'alice')}"}
        bob = {"Authorization": f"Session {_login(client, 'bob')}"}
        created = client.post(
            "/v1/scans/file",
            files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
            headers=alice,
        )
        assert created.status_code == 200
        scan_id = created.json()["scan_id"]
        for suffix in ("", "/report?format=markdown", "/report?format=sarif"):
            own = client.get(f"/v1/scans/{scan_id}{suffix}", headers=alice)
            foreign = client.get(f"/v1/scans/{scan_id}{suffix}", headers=bob)
            missing = client.get(f"/v1/scans/{uuid4()}{suffix}", headers=bob)
            assert own.status_code == 200
            assert own.headers["cache-control"] == "no-store"
            assert foreign.status_code == missing.status_code == 404
            assert foreign.json()["code"] == missing.json()["code"] == "scan_not_found"

        operator = client.get(
            f"/v1/scans/{scan_id}", headers={"Authorization": "Bearer operator-secret"}
        )
    assert operator.status_code == 200


def test_revoked_member_session_cannot_download_json_or_sarif() -> None:
    membership = MembershipService(InMemoryMembershipRepository())
    membership.register("alice", "secure-password-123")
    app = create_app(
        Settings(environment="production", testing=True),
        membership=membership,
    )
    with TestClient(app) as client:
        token = _login(client, "alice")
        headers = {"Authorization": f"Session {token}"}
        created = client.post(
            "/v1/scans/file",
            files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
            headers=headers,
        )
        assert created.status_code == 200
        scan_id = created.json()["scan_id"]
        membership.logout(token)
        assert client.get(f"/v1/scans/{scan_id}", headers=headers).status_code == 401
        assert (
            client.get(f"/v1/scans/{scan_id}/report?format=sarif", headers=headers).status_code
            == 401
        )
