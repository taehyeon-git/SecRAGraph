"""Member report ownership against real PostgreSQL and the FastAPI boundary."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.membership.service import MembershipService
from security_review.storage.database import create_session_factory
from security_review.storage.members import SqlAlchemyMembershipRepository
from security_review.storage.reports import SqlAlchemyReportRepository

pytestmark = pytest.mark.integration


def test_member_report_isolation_with_postgres() -> None:
    database_url = os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@127.0.0.1:55432/secragraph_test",
    )
    engine = create_engine(database_url, connect_args={"connect_timeout": 2})
    try:
        try:
            with engine.connect():
                pass
        except OperationalError as error:
            pytest.skip(f"PostgreSQL test database is unavailable: {error.__class__.__name__}")
        configuration = Config("alembic.ini")
        configuration.set_main_option("sqlalchemy.url", database_url)
        command.upgrade(configuration, "head")

        sessions = create_session_factory(database_url, engine=engine)
        membership = MembershipService(SqlAlchemyMembershipRepository(sessions))
        app = create_app(
            Settings(environment="production", testing=True),
            reports=SqlAlchemyReportRepository(sessions),
            membership=membership,
        )
        alice = f"alice-{uuid4().hex[:12]}"
        bob = f"bob-{uuid4().hex[:12]}"
        password = "integration-only-password"
        membership.register(alice, password)
        membership.register(bob, password)

        with TestClient(app) as client:

            def headers_for(username: str) -> dict[str, str]:
                response = client.post(
                    "/v1/auth/login", json={"username": username, "password": password}
                )
                assert response.status_code == 200
                return {"Authorization": f"Session {response.json()['token']}"}

            alice_headers = headers_for(alice)
            bob_headers = headers_for(bob)
            created = client.post(
                "/v1/scans/file",
                files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
                headers=alice_headers,
            )
            assert created.status_code == 200, created.text
            scan_id = created.json()["scan_id"]
            for suffix in ("", "/report?format=markdown", "/report?format=sarif"):
                path = f"/v1/scans/{scan_id}{suffix}"
                assert client.get(path, headers=alice_headers).status_code == 200
                denied = client.get(path, headers=bob_headers)
                assert denied.status_code == 404
                assert denied.json()["code"] == "scan_not_found"
    finally:
        engine.dispose()
