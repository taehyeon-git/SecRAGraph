"""The browser demo uses a member session instead of a shared operator key."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest

from apps.web.client import ApiClientError, SecRAGraphApiClient


class RecordingClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[httpx.Response]:
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        try:
            yield response
        finally:
            response.close()


def response(status: int, payload: object | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        json=payload,
        request=httpx.Request("POST", "http://api:8000/v1/auth/login"),
    )


def test_login_uses_no_shared_operator_token_and_validates_response() -> None:
    http = RecordingClient(
        [
            response(
                200,
                {
                    "token": "member-session-secret",
                    "username": "alice",
                    "expires_at": "2030-01-01T00:00:00Z",
                },
            )
        ]
    )
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    result = client.login("alice", "secure-password-123")

    assert result["token"] == "member-session-secret"
    assert http.calls == [
        (
            "POST",
            "http://api:8000/v1/auth/login",
            {"json": {"username": "alice", "password": "secure-password-123"}, "headers": {}},
        )
    ]


def test_member_session_is_used_for_scan_me_and_logout() -> None:
    session = "member-session-secret"
    http = RecordingClient(
        [
            response(200, {"user_id": "00000000-0000-0000-0000-000000000123", "username": "alice"}),
            response(200, {"scan_id": "scan-1", "findings": []}),
            httpx.Response(204, request=httpx.Request("POST", "http://api:8000/v1/auth/logout")),
        ]
    )
    client = SecRAGraphApiClient("http://api:8000", http_client=http, session_token=session)

    assert client.me()["username"] == "alice"
    assert client.scan_file("app.py", b"print('safe')\n", "text/x-python")["scan_id"] == "scan-1"
    client.logout()

    assert all(
        call[2]["headers"] == {"Authorization": "Session member-session-secret"}
        for call in http.calls
    )


def test_bad_login_payload_and_invalid_session_token_are_rejected() -> None:
    invalid_session = " bad "
    http = RecordingClient([response(200, {"token": "\nsecret", "username": "alice"})])
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    with pytest.raises(ApiClientError, match="invalid_api_response"):
        client.login("alice", "secure-password-123")
    with pytest.raises(ValueError, match="session token"):
        SecRAGraphApiClient("http://api:8000", http_client=http, session_token=invalid_session)


def test_member_401_does_not_echo_session_secret() -> None:
    session = "member-session-secret"
    http = RecordingClient(
        [response(401, {"code": "unauthorized", "message": "Authentication is required."})]
    )
    client = SecRAGraphApiClient("http://api:8000", http_client=http, session_token=session)

    with pytest.raises(ApiClientError) as captured:
        client.me()

    assert captured.value.status_code == 401
    assert "member-session-secret" not in str(captured.value)


def test_member_can_query_osv_with_version_and_cve_provenance() -> None:
    session = "member-session-secret"
    payload = {
        "ecosystem": "PyPI",
        "package": "jinja2",
        "version": "2.4.1",
        "advisories": [
            {
                "id": "GHSA-abcd-1234-5678",
                "cve_ids": ["CVE-2024-12345"],
                "summary": "Template issue",
                "published_at": "2024-01-01T00:00:00Z",
                "source_url": "https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
            }
        ],
    }
    http = RecordingClient([response(200, payload)])
    client = SecRAGraphApiClient("http://api:8000", http_client=http, session_token=session)

    result = client.query_vulnerabilities("PyPI", "jinja2", "2.4.1")

    assert result["advisories"][0]["cve_ids"] == ["CVE-2024-12345"]
    assert http.calls[0] == (
        "POST",
        "http://api:8000/v1/vulnerabilities/query",
        {
            "json": {"ecosystem": "PyPI", "package": "jinja2", "version": "2.4.1"},
            "headers": {"Authorization": f"Session {session}"},
        },
    )
