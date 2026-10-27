"""Member report ownership against real PostgreSQL and the FastAPI boundary."""

from __future__ import annotations

import os
from io import BytesIO
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from security_review.api.app import create_app
from security_review.application import ScanService
from security_review.config import Settings
from security_review.domain.models import Confidence, Finding, ScanExecution, Severity
from security_review.membership.service import MembershipService
from security_review.orchestrator.scan_graph import (
    DeterministicScanResult,
    ScanGraphServices,
    ScanRequest,
)
from security_review.storage.database import create_session_factory
from security_review.storage.members import SqlAlchemyMembershipRepository
from security_review.storage.reports import SqlAlchemyReportRepository

pytestmark = pytest.mark.integration


def _fixture_archive() -> bytes:
    archive = BytesIO()
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as output:
        output.writestr("src/app.py", "eval(user_input)\n")
        output.writestr("src/settings.py", 'API_KEY="demo-not-a-real-secret-12345"\n')
        output.writestr("infra/main.tf", 'resource "aws_security_group" "demo" {}\n')
    return archive.getvalue()


def _multiengine_fixture(request: ScanRequest) -> DeterministicScanResult:
    assert request.target.is_dir()
    for path in ("src/app.py", "src/settings.py", "infra/main.tf"):
        assert (request.target / path).is_file()
    findings = (
        Finding(
            id="OG:authenticated-sample",
            rule_id="OG/python-eval-flow",
            category="sast",
            severity=Severity.HIGH,
            file_path="src/app.py",
            line_start=1,
            message="Untrusted input reaches a dangerous operation.",
            redacted_evidence="[source omitted]",
            confidence=Confidence.MEDIUM,
            cwe_ids=("CWE-95",),
            remediation="Use a restricted parser.",
            engine="opengrep",
        ),
        Finding(
            id="GITLEAKS:authenticated-sample",
            rule_id="GITLEAKS/generic-api-key",
            category="secret",
            severity=Severity.HIGH,
            file_path="src/settings.py",
            line_start=1,
            message="Potential credential in source.",
            redacted_evidence="[REDACTED: secret value omitted]",
            confidence=Confidence.MEDIUM,
            cwe_ids=("CWE-798",),
            remediation="Move the credential to a secret store.",
            engine="gitleaks",
        ),
        Finding(
            id="CHECKOV:authenticated-sample",
            rule_id="CKV_AWS_SAMPLE",
            category="configuration",
            severity=Severity.MEDIUM,
            file_path="infra/main.tf",
            line_start=1,
            message="Synthetic infrastructure policy finding.",
            redacted_evidence="[configuration snippet omitted]",
            confidence=Confidence.MEDIUM,
            cwe_ids=("CWE-284",),
            remediation="Restrict the resource configuration.",
            engine="checkov",
        ),
    )
    executions = tuple(
        ScanExecution(
            engine=engine,
            kind=kind,
            status="completed",
            version="test-fixture",
            elapsed_ms=1,
            eligible_files=(path,),
            scanned_files=(path,),
            languages=(language,),
            checks=(check,),
        )
        for engine, kind, path, language, check in (
            ("opengrep", "sast", "src/app.py", "python", "OG/python-eval-flow"),
            ("gitleaks", "secret", "src/settings.py", "python", "builtin-default"),
            ("checkov", "configuration", "infra/main.tf", "terraform", "CKV_AWS_SAMPLE"),
        )
    )
    return DeterministicScanResult(
        target_name=request.target_name or "source.zip",
        findings=findings,
        executions=executions,
    )


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
        reports = SqlAlchemyReportRepository(sessions)
        app = create_app(
            Settings(environment="development", testing=True, allow_self_registration=True),
            reports=reports,
            membership=membership,
        )
        app.state.scan_service = ScanService(
            reports,
            graph_services=ScanGraphServices(deterministic_scanner=_multiengine_fixture),
        )
        alice = f"alice-{uuid4().hex[:12]}"
        bob = f"bob-{uuid4().hex[:12]}"
        password = "integration-only-password"
        with TestClient(app) as client:
            for username in (alice, bob):
                registered = client.post(
                    "/v1/auth/register", json={"username": username, "password": password}
                )
                assert registered.status_code == 201

            def headers_for(username: str) -> dict[str, str]:
                response = client.post(
                    "/v1/auth/login", json={"username": username, "password": password}
                )
                assert response.status_code == 200
                return {"Authorization": f"Session {response.json()['token']}"}

            alice_headers = headers_for(alice)
            bob_headers = headers_for(bob)
            created = client.post(
                "/v1/scans/archive",
                files={"file": ("source.zip", _fixture_archive(), "application/zip")},
                headers=alice_headers,
            )
            assert created.status_code == 200, created.text
            assert created.json()["target_name"] == "source.zip"
            assert {item["engine"] for item in created.json()["executions"]} == {
                "opengrep",
                "gitleaks",
                "checkov",
            }
            assert {item["file_path"] for item in created.json()["findings"]} == {
                "src/app.py",
                "src/settings.py",
                "infra/main.tf",
            }
            assert "demo-not-a-real-secret-12345" not in created.text
            scan_id = created.json()["scan_id"]
            for suffix in ("", "/report?format=markdown", "/report?format=sarif"):
                path = f"/v1/scans/{scan_id}{suffix}"
                owned = client.get(path, headers=alice_headers)
                assert owned.status_code == 200
                assert "demo-not-a-real-secret-12345" not in owned.text
                if not suffix:
                    assert owned.json() == created.json()
                denied = client.get(path, headers=bob_headers)
                assert denied.status_code == 404
                assert denied.json()["code"] == "scan_not_found"
    finally:
        engine.dispose()
