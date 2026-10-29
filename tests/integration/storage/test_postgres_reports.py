from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from security_review.domain.models import (
    Confidence,
    Finding,
    ScanExecution,
    Severity,
    TraceLocation,
)
from security_review.ports import ReportRepositoryError
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif
from security_review.scanner.external_detectors import _parse_gitleaks
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
        id="OG:stable",
        rule_id="OG/python-eval-flow",
        category="sast",
        severity=Severity.HIGH,
        file_path="src/app.py",
        line_start=4,
        message="Dynamic evaluation detected.",
        redacted_evidence="eval(user_input)",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-95",),
        remediation="Use an explicit parser.",
        engine="opengrep",
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


def test_postgres_repository_round_trips_execution_coverage_and_trace(
    session_factory: sessionmaker[Session],
) -> None:
    finding = sample_finding().model_copy(
        update={
            "engine": "opengrep",
            "trace": (
                TraceLocation(file_path="src/route.py", line_start=2, role="source"),
                TraceLocation(file_path="src/app.py", line_start=4, role="sink"),
            ),
        }
    )
    execution = ScanExecution(
        engine="opengrep",
        kind="sast",
        status="partial",
        version="1.32.0",
        elapsed_ms=123,
        eligible_files=("src/route.py", "src/app.py"),
        scanned_files=("src/app.py",),
        languages=("python",),
        checks=("OG/taint",),
        reason="scan_partial",
    )
    report = build_report("repo", [finding], executions=(execution,))
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)

    assert repository.get(report.scan_id) == report


def test_postgres_repository_round_trips_http_finding_without_source_location(
    session_factory: sessionmaker[Session],
) -> None:
    http = Finding(
        id="zap:10021:GET:/public",
        rule_id="ZAP/10021",
        category="dast",
        severity=Severity.MEDIUM,
        http_method="GET",
        http_path="/public",
        message="Missing security header.",
        redacted_evidence="Response header presence only.",
        confidence=Confidence.HIGH,
        remediation="Set the header.",
        engine="zap",
    )
    execution = ScanExecution(
        engine="zap",
        kind="dast",
        status="completed",
        elapsed_ms=20,
        eligible_endpoints=("GET /public",),
        observed_alert_endpoints=("GET /public",),
        checks=("passive",),
    )
    report = build_report("api", [http, sample_finding()], executions=(execution,))
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)

    assert repository.get(report.scan_id) == report


def test_postgres_repository_persists_historical_commit_provenance(
    session_factory: sessionmaker[Session],
) -> None:
    commit = "a" * 40
    finding = sample_finding().model_copy(update={"git_commit": commit})
    execution = ScanExecution(
        engine="gitleaks",
        kind="secret",
        status="completed",
        elapsed_ms=15,
        revision_head=commit,
        selected_commit_count=1,
    )
    report = build_report("repo", [finding], executions=(execution,))
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)

    assert repository.get(report.scan_id) == report
    with session_factory() as session:
        assert (
            session.scalar(
                text("SELECT git_commit FROM app.findings WHERE scan_id = :scan_id"),
                {"scan_id": report.scan_id},
            )
            == commit
        )


def test_postgres_repository_round_trips_image_finding_and_execution(
    session_factory: sessionmaker[Session],
) -> None:
    from datetime import UTC, datetime

    image_id = "sha256:" + "a" * 64
    finding = Finding(
        id="trivy:pkg:apt:cve",
        rule_id="CVE-2026-12345",
        category="container_vulnerability",
        severity=Severity.HIGH,
        image_id=image_id,
        image_resource="pkg:deb/debian/apt@2.6.1",
        upstream_severity="HIGH",
        severity_source="debian",
        message="Installed package has an advisory.",
        redacted_evidence="apt 2.6.1",
        confidence=Confidence.HIGH,
        remediation="Upgrade the package.",
        engine="trivy",
    )
    execution = ScanExecution(
        engine="trivy",
        kind="container",
        status="completed",
        version="0.76.1",
        elapsed_ms=1200,
        image_id=image_id,
        image_local_id="sha256:" + "b" * 64,
        image_tar_sha256="c" * 64,
        image_db_updated_at=datetime(2026, 10, 29, 13, 9, tzinfo=UTC),
        image_vulnerability_count=1,
        image_config_count=0,
        sbom_sha256="d" * 64,
        sbom_component_count=386,
        checks=("os-pkgs", "lang-pkgs", "image-config"),
    )
    report = build_report("image", [finding], executions=(execution,))
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)

    assert repository.get(report.scan_id) == report


def test_database_rejects_image_identity_on_source_location(
    session_factory: sessionmaker[Session],
) -> None:
    report = build_report("repo", [sample_finding()])
    SqlAlchemyReportRepository(session_factory).save(report)

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE app.findings SET image_id = :image_id, "
                    "image_resource = 'pkg:deb/debian/apt@1', upstream_severity = 'HIGH' "
                    "WHERE scan_id = :scan_id"
                ),
                {"image_id": "sha256:" + "a" * 64, "scan_id": report.scan_id},
            )


def test_database_rejects_http_location_with_historical_commit(
    session_factory: sessionmaker[Session],
) -> None:
    report = build_report("repo", [sample_finding()])
    SqlAlchemyReportRepository(session_factory).save(report)

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text(
                    "UPDATE app.findings SET file_path = NULL, line_start = NULL, "
                    "http_method = 'GET', http_path = '/api', git_commit = :commit "
                    "WHERE scan_id = :scan_id"
                ),
                {"commit": "a" * 40, "scan_id": report.scan_id},
            )


def test_database_rejects_abbreviated_historical_commit(
    session_factory: sessionmaker[Session],
) -> None:
    report = build_report("repo", [sample_finding()])
    SqlAlchemyReportRepository(session_factory).save(report)

    with pytest.raises(IntegrityError):
        with session_factory.begin() as session:
            session.execute(
                text("UPDATE app.findings SET git_commit = 'abc123' WHERE scan_id = :scan_id"),
                {"scan_id": report.scan_id},
            )


def test_persisted_scan_never_restores_unrecognized_source_line_content(
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    canary = "opaque-canary-12345"
    (tmp_path / "app.py").write_text(f"API_KEY={canary}\n", encoding="utf-8")
    findings = _parse_gitleaks(
        [
            {
                "RuleID": "generic-api-key",
                "File": "app.py",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "Secret": canary,
                "Match": f"API_KEY={canary}",
            }
        ],
        tmp_path,
        frozenset({"app.py"}),
    )
    report = build_report("app.py", findings)
    repository = SqlAlchemyReportRepository(session_factory)

    repository.save(report)
    restored = repository.get(report.scan_id)

    assert restored is not None
    for rendered in (
        restored.model_dump_json(),
        render_json(restored),
        render_markdown(restored),
        render_sarif(restored),
    ):
        assert canary not in rendered


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
