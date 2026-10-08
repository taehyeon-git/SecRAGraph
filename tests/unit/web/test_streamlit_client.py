"""The demo UI remains an HTTP-only client of the backend API."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from apps.web import streamlit_app
from apps.web.client import (
    MAX_UPLOAD_BYTES,
    ApiClientError,
    SecRAGraphApiClient,
    safe_source_url,
    validate_api_base_url,
)


class RecordingHttpClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def stream(
        self,
        method: str,
        url: str,
        **kwargs: object,
    ) -> Iterator[httpx.Response]:
        assert method == "POST"
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        try:
            yield response
        finally:
            response.close()


def _response(status_code: int, payload: object) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=payload,
        request=httpx.Request("POST", "http://api:8000/test"),
    )


def _knowledge_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "intent": "rag",
        "answer": "safe",
        "attempts": 1,
        "sources": [],
        "warnings": [],
    }
    payload.update(overrides)
    return payload


def test_knowledge_query_uses_only_the_http_endpoint() -> None:
    http = RecordingHttpClient([_response(200, _knowledge_payload())])
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    result = client.query_knowledge("  How do I prevent injection?  ")

    assert result["answer"] == "safe"
    assert http.calls == [
        (
            "http://api:8000/v1/knowledge/query",
            {"json": {"question": "How do I prevent injection?"}},
        )
    ]


def test_file_scan_uses_the_file_endpoint_and_multipart_metadata() -> None:
    http = RecordingHttpClient([_response(200, {"scan_id": "scan-1", "findings": []})])
    client = SecRAGraphApiClient("http://api:8000/", http_client=http)

    result = client.scan_file("app.py", b"print('safe')\n", "text/x-python")

    assert result["scan_id"] == "scan-1"
    assert http.calls == [
        (
            "http://api:8000/v1/scans/file",
            {"files": {"file": ("app.py", b"print('safe')\n", "text/x-python")}},
        )
    ]


def test_typed_api_error_is_preserved_without_echoing_details() -> None:
    http = RecordingHttpClient(
        [
            _response(
                503,
                {
                    "code": "knowledge_dependency_unavailable",
                    "message": "A knowledge dependency is unavailable.",
                    "details": "private-upstream-host",
                },
            )
        ]
    )
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    with pytest.raises(ApiClientError) as captured:
        client.query_knowledge("question")

    assert captured.value.status_code == 503
    assert captured.value.code == "knowledge_dependency_unavailable"
    assert captured.value.message == "A knowledge dependency is unavailable."
    assert "private-upstream-host" not in str(captured.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "api:8000",
        "file:///etc/passwd",
        "http://user:password@api:8000",
        "http://api:8000?secret=value",
        "http://api:8000/#fragment",
    ],
)
def test_api_base_url_rejects_unsafe_values(base_url: str) -> None:
    with pytest.raises(ValueError, match="API base URL"):
        validate_api_base_url(base_url)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://example.com/guide", "https://example.com/guide"),
        ("http://example.com", "http://example.com"),
        ("javascript:alert(1)", None),
        ("data:text/html,<script>alert(1)</script>", None),
        ("//example.com/guide", None),
        ("https://user:secret@example.com", None),
        ("https://example.com/guide ", None),
        ("https://example.com/guide\nspoof", None),
        ("http://[", None),
        (None, None),
    ],
)
def test_source_links_are_allowlisted(value: object, expected: str | None) -> None:
    assert safe_source_url(value) == expected


@pytest.mark.parametrize("question", ["", "   ", "x" * 2_001, "bad\x00question"])
def test_client_rejects_invalid_questions_without_network_calls(question: str) -> None:
    http = RecordingHttpClient([])
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    with pytest.raises(ValueError, match="question"):
        client.query_knowledge(question)

    assert http.calls == []


def test_invalid_or_oversized_api_responses_are_typed() -> None:
    invalid_json = httpx.Response(
        200,
        content=b"not-json",
        request=httpx.Request("POST", "http://api:8000/test"),
    )
    oversized = httpx.Response(
        200,
        content=b"x" * 1_000_001,
        request=httpx.Request("POST", "http://api:8000/test"),
    )

    for response in (invalid_json, oversized):
        client = SecRAGraphApiClient(
            "http://api:8000",
            http_client=RecordingHttpClient([response]),
        )
        with pytest.raises(ApiClientError) as captured:
            client.query_knowledge("question")
        assert captured.value.code == "invalid_api_response"


class _TrackingByteStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.yielded = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._chunks:
            self.yielded += 1
            yield chunk


def test_chunked_response_stops_at_the_client_size_limit() -> None:
    stream = _TrackingByteStream(
        [
            b"x" * 500_000,
            b"x" * 500_000,
            b"x",
            b"must-not-be-read",
        ]
    )

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, request=request)

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        client = SecRAGraphApiClient("http://api:8000", http_client=http)
        with pytest.raises(ApiClientError) as captured:
            client.query_knowledge("question")

    assert captured.value.code == "invalid_api_response"
    assert stream.yielded == 3


def test_oversized_content_length_is_rejected_without_reading_the_body() -> None:
    stream = _TrackingByteStream([b"must-not-be-read"])

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "1000001"},
            stream=stream,
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(respond)) as http:
        client = SecRAGraphApiClient("http://api:8000", http_client=http)
        with pytest.raises(ApiClientError) as captured:
            client.query_knowledge("question")

    assert captured.value.code == "invalid_api_response"
    assert stream.yielded == 0


def test_streamlit_layer_does_not_import_graph_or_database_internals() -> None:
    sources = (
        Path("apps/web/client.py").read_text(encoding="utf-8"),
        Path("apps/web/streamlit_app.py").read_text(encoding="utf-8"),
    )

    forbidden = (
        "security_review.orchestrator",
        "security_review.storage",
        "sqlalchemy",
        "qdrant_client",
    )
    assert not any(name in source for source in sources for name in forbidden)


def test_response_payload_must_be_a_json_object() -> None:
    client = SecRAGraphApiClient(
        "http://api:8000",
        http_client=RecordingHttpClient([_response(200, ["not", "an", "object"])]),
    )

    with pytest.raises(ApiClientError, match="invalid_api_response"):
        client.query_knowledge("question")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        _knowledge_payload(intent="arbitrary"),
        _knowledge_payload(answer=""),
        _knowledge_payload(attempts=True),
        _knowledge_payload(sources={"id": "not-a-list"}),
        _knowledge_payload(warnings=[42]),
        _knowledge_payload(
            sources=[
                {
                    "id": "guide:1",
                    "title": "Guide",
                    "source_url": None,
                    "page": 0,
                    "section": None,
                    "score": 0.9,
                }
            ]
        ),
    ],
)
def test_malformed_successful_knowledge_payload_is_rejected(payload: object) -> None:
    client = SecRAGraphApiClient(
        "http://api:8000",
        http_client=RecordingHttpClient([_response(200, payload)]),
    )

    with pytest.raises(ApiClientError) as captured:
        client.query_knowledge("question")

    assert captured.value.status_code == 200
    assert captured.value.code == "invalid_api_response"


def test_http_client_protocol_accepts_httpx_style_keyword_arguments() -> None:
    response = _response(200, _knowledge_payload(answer="ok"))
    http: Any = RecordingHttpClient([response])

    result = SecRAGraphApiClient("http://api:8000", http_client=http).query_knowledge("question")

    assert result == _knowledge_payload(answer="ok")


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (httpx.ReadTimeout("slow upstream"), "api_timeout"),
        (httpx.ConnectError("unreachable upstream"), "api_unreachable"),
    ],
)
def test_network_failures_are_mapped_to_fixed_client_errors(
    error: httpx.RequestError,
    expected_code: str,
) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        error.request = request
        raise error

    with httpx.Client(transport=httpx.MockTransport(fail)) as http:
        client = SecRAGraphApiClient("http://api:8000", http_client=http)
        with pytest.raises(ApiClientError) as captured:
            client.query_knowledge("question")

    assert captured.value.code == expected_code
    assert "upstream" not in captured.value.message


def test_oversized_file_is_rejected_before_an_http_request() -> None:
    http = RecordingHttpClient([])
    client = SecRAGraphApiClient("http://api:8000", http_client=http)

    with pytest.raises(ValueError, match="upload limit"):
        client.scan_file(
            "app.py",
            b"x" * (MAX_UPLOAD_BYTES + 1),
            "text/x-python",
        )

    assert http.calls == []


class _RecordingStreamlit:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.writes: list[object] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.metrics: list[tuple[str, object]] = []
        self.links: list[tuple[str, str]] = []

    def subheader(self, _value: str) -> None:
        return None

    def text(self, value: str) -> None:
        self.texts.append(value)

    def write(self, value: object) -> None:
        self.writes.append(value)

    def error(self, value: str) -> None:
        self.errors.append(value)

    def warning(self, value: str) -> None:
        self.warnings.append(value)

    def metric(self, label: str, value: object) -> None:
        self.metrics.append((label, value))

    def json(self, _value: object) -> None:
        return None

    def link_button(self, label: str, url: str) -> None:
        self.links.append((label, url))


def test_remote_knowledge_text_is_rendered_plain_and_without_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RecordingStreamlit()
    answer = "# provider heading\n[unsafe label](javascript:alert(1))\n" + "a" * 600
    warning = "[warning](https://attacker.example)"
    title = "![tracking pixel](https://attacker.example/pixel)"
    monkeypatch.setattr(streamlit_app, "st", fake)

    streamlit_app._show_knowledge_result(
        _knowledge_payload(
            answer=answer,
            warnings=[warning],
            sources=[
                {
                    "id": "guide:1",
                    "title": title,
                    "source_url": "https://example.com/guide",
                    "page": None,
                    "section": None,
                    "score": 0.9,
                }
            ],
        )
    )

    assert answer in fake.texts
    assert warning in fake.texts
    assert title in fake.texts
    assert fake.writes == []
    assert warning not in fake.warnings
    assert fake.links == [("Open source 1", "https://example.com/guide")]


def test_long_validated_sql_provenance_is_accepted_and_rendered_as_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RecordingStreamlit()
    monkeypatch.setattr(streamlit_app, "st", fake)
    sql = "SELECT cwe_id FROM intel.cwe WHERE " + "cwe_id = 'CWE-95' OR " * 40 + "TRUE"
    source = {
        "id": "sql:intel.cwe",
        "title": "intel.cwe",
        "source_url": None,
        "page": None,
        "section": sql,
        "score": None,
    }
    payload = _knowledge_payload(intent="text2sql", sources=[source])
    client = SecRAGraphApiClient(
        "http://api:8000",
        http_client=RecordingHttpClient([_response(200, payload)]),
    )

    result = client.query_knowledge("How many CWE records?")
    streamlit_app._show_knowledge_result(result)

    assert result["sources"][0]["section"] == sql
    assert sql in fake.texts
    assert fake.writes == []


def test_multiline_sql_provenance_is_accepted_as_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RecordingStreamlit()
    monkeypatch.setattr(streamlit_app, "st", fake)
    sql = "SELECT 'line one\nline two' FROM intel.cwe LIMIT 5"
    payload = _knowledge_payload(
        intent="text2sql",
        sources=[
            {
                "id": "sql:intel.cwe",
                "title": "intel.cwe",
                "source_url": None,
                "page": None,
                "section": sql,
                "score": None,
            }
        ],
    )
    client = SecRAGraphApiClient(
        "http://api:8000", http_client=RecordingHttpClient([_response(200, payload)])
    )

    result = client.query_knowledge("question")
    streamlit_app._show_knowledge_result(result)

    assert sql in fake.texts
    assert fake.writes == []


def test_rag_section_retains_its_existing_character_bound() -> None:
    section = "보안" * 200
    payload = _knowledge_payload(
        sources=[
            {
                "id": "guide:1",
                "title": "Guide",
                "source_url": None,
                "page": None,
                "section": section,
                "score": 0.9,
            }
        ]
    )
    client = SecRAGraphApiClient(
        "http://api:8000", http_client=RecordingHttpClient([_response(200, payload)])
    )

    assert client.query_knowledge("question")["sources"][0]["section"] == section


def test_remote_api_error_text_is_not_sent_to_a_markdown_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RecordingStreamlit()
    monkeypatch.setattr(streamlit_app, "st", fake)
    remote_message = "![tracking](https://attacker.example/pixel)"

    streamlit_app._show_client_error(
        ApiClientError(503, "dependency_unavailable", remote_message, "request-1")
    )

    assert fake.errors == ["The API request failed."]
    assert any(remote_message in text for text in fake.texts)


@pytest.mark.parametrize("total", [None, True, -1, "many", object()])
def test_scan_summary_total_is_robust_to_malformed_values(
    total: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RecordingStreamlit()
    monkeypatch.setattr(streamlit_app, "st", fake)

    streamlit_app._show_scan_result({"summary": {"total": total}})

    assert fake.metrics == [("Findings", "Unavailable")]


class _Tab:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        return None


class _OversizedUpload:
    name = "large.py"
    type = "text/x-python"
    size = MAX_UPLOAD_BYTES + 1

    def getvalue(self) -> bytes:
        raise AssertionError("oversized uploads must not be read into memory")


class _MainStreamlit(_RecordingStreamlit):
    def __init__(self) -> None:
        super().__init__()
        self._button_calls = 0

    def set_page_config(self, **_kwargs: object) -> None:
        return None

    def title(self, _value: str) -> None:
        return None

    def caption(self, _value: str) -> None:
        return None

    def tabs(self, _labels: list[str]) -> tuple[_Tab, _Tab]:
        return _Tab(), _Tab()

    def file_uploader(self, *_args: object, **_kwargs: object) -> _OversizedUpload:
        return _OversizedUpload()

    def button(self, _label: str, **_kwargs: object) -> bool:
        self._button_calls += 1
        return self._button_calls == 1

    def text_area(self, *_args: object, **_kwargs: object) -> str:
        return ""


def test_streamlit_checks_upload_size_before_getvalue_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _MainStreamlit()
    monkeypatch.setattr(streamlit_app, "st", fake)

    streamlit_app.main()

    assert fake.errors == ["The selected file exceeds the client upload limit."]
