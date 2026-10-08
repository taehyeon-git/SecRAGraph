from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.domain.models import ScanReport
from security_review.ports import ReportRepositoryError


class FakeReportRepository:
    def __init__(self) -> None:
        self.reports: dict[UUID, ScanReport] = {}

    def save(self, report: ScanReport) -> None:
        self.reports[report.scan_id] = report

    def get(self, scan_id: UUID) -> ScanReport | None:
        return self.reports.get(scan_id)


class UnavailableReportRepository:
    def save(self, report: ScanReport) -> None:
        del report
        raise ReportRepositoryError("postgres-password-must-not-leak")

    def get(self, scan_id: UUID) -> ScanReport | None:
        del scan_id
        raise ReportRepositoryError("postgres-password-must-not-leak")


@pytest.fixture
def repository() -> FakeReportRepository:
    return FakeReportRepository()


@pytest.fixture
def app(repository: FakeReportRepository) -> FastAPI:
    return create_app(Settings(testing=True), reports=repository)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def upload_sample(client: TestClient) -> ScanReport:
    response = client.post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )
    assert response.status_code == 200
    return ScanReport.model_validate(response.json())


def test_scan_is_saved_before_response(
    client: TestClient,
    repository: FakeReportRepository,
) -> None:
    report = upload_sample(client)

    assert repository.get(report.scan_id) == report


def test_saved_scan_can_be_retrieved_as_canonical_json(client: TestClient) -> None:
    report = upload_sample(client)

    response = client.get(f"/v1/scans/{report.scan_id}")

    assert response.status_code == 200
    assert ScanReport.model_validate(response.json()) == report


def test_unknown_scan_returns_typed_404(client: TestClient) -> None:
    response = client.get(f"/v1/scans/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["code"] == "scan_not_found"


def test_invalid_scan_id_returns_stable_validation_error(client: TestClient) -> None:
    response = client.get("/v1/scans/not-a-uuid")

    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_unsupported_report_format_is_typed_422(client: TestClient) -> None:
    report = upload_sample(client)

    response = client.get(f"/v1/scans/{report.scan_id}/report?format=pdf")

    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_markdown_and_sarif_render_the_same_persisted_report(client: TestClient) -> None:
    report = upload_sample(client)

    markdown = client.get(f"/v1/scans/{report.scan_id}/report?format=markdown")
    sarif = client.get(f"/v1/scans/{report.scan_id}/report?format=sarif")

    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert str(report.scan_id) in markdown.text
    assert sarif.status_code == 200
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    sarif_payload = json.loads(sarif.text)
    assert sarif_payload["runs"][0]["results"][0]["ruleId"] == "PY001"


def test_repository_failure_returns_typed_503_without_private_details() -> None:
    app = create_app(Settings(testing=True), reports=UnavailableReportRepository())
    client = TestClient(app, raise_server_exceptions=False)

    scan_response = client.post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )
    get_response = client.get(f"/v1/scans/{uuid4()}")

    assert scan_response.status_code == 503
    assert scan_response.json()["code"] == "dependency_unavailable"
    assert get_response.status_code == 503
    assert get_response.json()["code"] == "dependency_unavailable"
    assert "postgres-password" not in scan_response.text + get_response.text
