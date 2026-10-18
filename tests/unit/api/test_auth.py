from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from security_review.api.app import create_app
from security_review.config import Settings


def test_production_api_requires_nonblank_token_even_in_testing_mode() -> None:
    for token in (None, SecretStr(""), SecretStr("   ")):
        with pytest.raises(ValueError, match="API token"):
            create_app(Settings(environment="production", testing=True, api_token=token))


def test_auth_gate_covers_upload_retrieval_and_knowledge_before_body_parsing() -> None:
    app = create_app(Settings(testing=True, api_token=SecretStr("test-only-token")))
    with TestClient(app) as client:
        for path, method in (
            ("/v1/scans/file", "post"),
            ("/v1/scans/00000000-0000-0000-0000-000000000000", "get"),
            ("/v1/knowledge/query", "post"),
        ):
            request = getattr(client, method)
            request_body = {"content": b"{" * 100} if method == "post" else {}
            missing = request(path, **request_body)
            incorrect = request(
                path,
                headers={"Authorization": "Bearer wrong-token"},
                **request_body,
            )
            assert missing.status_code == incorrect.status_code == 401
            assert missing.json()["code"] == incorrect.json()["code"] == "unauthorized"
            assert "test-only-token" not in missing.text + incorrect.text

        authenticated = client.get(
            "/v1/scans/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": "Bearer test-only-token"},
        )
        assert authenticated.status_code == 404
        assert client.get("/health/live").status_code == 200


def test_unauthenticated_large_body_is_rejected_before_body_limit() -> None:
    app = create_app(
        Settings(testing=True, api_token=SecretStr("test-only-token"), max_request_bytes=10)
    )
    with TestClient(app) as client:
        response = client.post("/v1/scans/file", content=b"x" * 100)

    assert response.status_code == 401


def test_development_without_token_remains_explicitly_unguarded() -> None:
    app = create_app(Settings(environment="development", testing=True, api_token=None))
    with TestClient(app) as client:
        response = client.post("/v1/knowledge/query", json={"question": "CWE-95?"})
    assert response.status_code == 503
