from __future__ import annotations

import os

import httpx
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def live_client() -> httpx.Client:
    base_url = os.getenv("SECRAGRAPH_TEST_API_URL", "http://127.0.0.1:8000")
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        yield client


def test_live_stack_reports_database_readiness(live_client: httpx.Client) -> None:
    response = live_client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "dependencies": {"postgres": True, "qdrant": True},
        "reasons": {},
    }


def test_uploaded_scan_can_be_retrieved_in_all_formats(live_client: httpx.Client) -> None:
    response = live_client.post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )

    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    stored = live_client.get(f"/v1/scans/{scan_id}")
    markdown = live_client.get(f"/v1/scans/{scan_id}/report?format=markdown")
    sarif = live_client.get(f"/v1/scans/{scan_id}/report?format=sarif")
    assert stored.status_code == 200
    assert stored.json() == response.json()
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert sarif.status_code == 200
    assert sarif.headers["content-type"].startswith("application/sarif+json")
