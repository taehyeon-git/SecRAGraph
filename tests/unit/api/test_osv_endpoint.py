"""OSV lookups share the protected API boundary and never need an OSV key."""

from __future__ import annotations

from fastapi.testclient import TestClient
from pydantic import SecretStr

from security_review.api.app import create_app
from security_review.config import Settings
from security_review.intelligence.osv import OsvAdvisory, OsvQueryResult, OsvUnavailableError


class FakeOsv:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.fail = fail

    def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
        self.calls.append((ecosystem, package, version))
        if self.fail:
            raise OsvUnavailableError()
        return OsvQueryResult(
            ecosystem,
            package,
            version,
            (
                OsvAdvisory(
                    "GHSA-abcd-1234-5678",
                    ("CVE-2024-12345",),
                    "Template processing issue",
                    "2024-01-01T00:00:00Z",
                    "https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
                ),
            ),
        )


def test_osv_route_requires_auth_and_returns_version_scoped_evidence() -> None:
    fake = FakeOsv()
    app = create_app(
        Settings(testing=True, api_token=SecretStr("operator-secret")),
        osv_client=fake,
    )
    payload = {"ecosystem": "PyPI", "package": "jinja2", "version": "2.4.1"}
    with TestClient(app) as client:
        denied = client.post("/v1/vulnerabilities/query", json=payload)
        allowed = client.post(
            "/v1/vulnerabilities/query",
            json=payload,
            headers={"Authorization": "Bearer operator-secret"},
        )
    assert denied.status_code == 401
    assert allowed.status_code == 200
    assert allowed.json()["advisories"][0]["cve_ids"] == ["CVE-2024-12345"]
    assert fake.calls == [("PyPI", "jinja2", "2.4.1")]


def test_osv_provider_failure_is_safe_and_does_not_imply_clean() -> None:
    app = create_app(Settings(testing=True), osv_client=FakeOsv(fail=True))
    with TestClient(app) as client:
        response = client.post(
            "/v1/vulnerabilities/query",
            json={"ecosystem": "PyPI", "package": "jinja2", "version": "2.4.1"},
        )
    assert response.status_code == 503
    assert response.json()["code"] == "osv_unavailable"
