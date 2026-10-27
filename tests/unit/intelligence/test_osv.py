"""Bounded, offline OSV package/version CVE evidence tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from security_review.intelligence.osv import OsvClient, OsvInputError, OsvUnavailableError


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class AdvanceBeforeYieldStream(httpx.SyncByteStream):
    def __init__(self, clock: FakeClock, value: float, content: bytes) -> None:
        self._clock = clock
        self._value = value
        self._content = content

    def __iter__(self) -> Iterator[bytes]:
        self._clock.value = self._value
        yield self._content


class AdvanceAfterYieldStream(httpx.SyncByteStream):
    def __init__(self, clock: FakeClock, value: float, content: bytes) -> None:
        self._clock = clock
        self._value = value
        self._content = content

    def __iter__(self) -> Iterator[bytes]:
        yield self._content
        self._clock.value = self._value


def _advisory(
    *,
    identifier: str = "GHSA-abcd-1234-5678",
    aliases: list[str] | None = None,
    withdrawn: str | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "aliases": aliases if aliases is not None else ["CVE-2024-12345"],
        "summary": "Template processing issue",
        "published": "2024-01-01T00:00:00Z",
        "withdrawn": withdrawn,
        "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"}}],
    }


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_osv_query_returns_only_real_cve_aliases_with_provenance() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.osv.dev/v1/query"
        assert json.loads(request.content) == {
            "package": {"ecosystem": "PyPI", "name": "jinja2"},
            "version": "2.4.1",
        }
        return httpx.Response(200, json={"vulns": [_advisory()]})

    with _client(respond) as http:
        result = OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")

    assert result.package == "jinja2"
    assert result.version == "2.4.1"
    assert result.advisories[0].cve_ids == ("CVE-2024-12345",)
    assert result.advisories[0].source_url == "https://osv.dev/vulnerability/GHSA-abcd-1234-5678"


def test_no_cve_alias_is_not_relabelled_as_a_cve() -> None:
    def response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [_advisory(aliases=[])]})

    with _client(response) as http:
        result = OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")
    assert result.advisories[0].cve_ids == ()


def test_primary_cve_id_is_included_without_an_alias() -> None:
    with _client(
        lambda _request: httpx.Response(
            200,
            json={"vulns": [_advisory(identifier="CVE-2026-12345", aliases=[])]},
        )
    ) as http:
        result = OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")

    assert result.advisories[0].cve_ids == ("CVE-2026-12345",)


def test_withdrawn_or_other_package_records_are_not_presented() -> None:
    other = _advisory(identifier="GHSA-other-1234-5678")
    other["affected"][0]["package"]["name"] = "other"
    with _client(
        lambda _request: httpx.Response(
            200, json={"vulns": [_advisory(withdrawn="2025-01-01T00:00:00Z"), other]}
        )
    ) as http:
        result = OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")
    assert result.advisories == ()


def test_paginated_results_are_deduplicated() -> None:
    calls: list[dict[str, object]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(200, json={"vulns": [_advisory()], "next_page_token": "next"})
        return httpx.Response(200, json={"vulns": [_advisory()]})

    with _client(respond) as http:
        result = OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")
    assert len(result.advisories) == 1
    assert calls[1]["page_token"] == "next"


@pytest.mark.parametrize("payload", [{"vulns": "wrong"}, {"vulns": [{"id": "../bad"}]}])
def test_malformed_provider_payload_fails_closed(payload: object) -> None:
    with _client(lambda _request: httpx.Response(200, json=payload)) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")


def test_response_size_and_page_cycles_are_bounded() -> None:
    with _client(lambda _request: httpx.Response(200, content=b"x" * 1_000_001)) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")

    def response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [], "next_page_token": "again"})

    with _client(response) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")


@pytest.mark.parametrize("value", ["", "../x", "x\nprivate", "a" * 300])
def test_bad_package_input_never_calls_network(value: str) -> None:
    with _client(lambda _request: pytest.fail("unexpected network call")) as http:
        with pytest.raises(OsvInputError):
            OsvClient(http).query_package("PyPI", value, "2.4.1")


def test_provider_errors_have_safe_public_error() -> None:
    with _client(lambda _request: httpx.Response(429, json={"private": "upstream-secret"})) as http:
        with pytest.raises(OsvUnavailableError) as captured:
            OsvClient(http).query_package("PyPI", "jinja2", "2.4.1")
    assert "upstream-secret" not in str(captured.value)


def test_optional_deadline_blocks_request_and_expired_stream_chunk() -> None:
    expired = FakeClock(5.0)
    with _client(lambda _request: pytest.fail("deadline must block the request")) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http, deadline=5.0, clock=expired).query_package("PyPI", "jinja2", "2.4.1")

    clock = FakeClock()
    payload = json.dumps({"vulns": []}).encode("utf-8")
    with _client(
        lambda _request: httpx.Response(
            200,
            stream=AdvanceBeforeYieldStream(clock, 5.0, payload),
        )
    ) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http, deadline=5.0, clock=clock).query_package("PyPI", "jinja2", "2.4.1")


def test_deadline_caps_request_timeout_and_is_checked_before_next_page() -> None:
    clock = FakeClock(7.0)
    timeouts: list[dict[str, float]] = []
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        timeouts.append(request.extensions["timeout"])
        payload = json.dumps({"vulns": [], "next_page_token": "next"}).encode("utf-8")
        return httpx.Response(
            200,
            stream=AdvanceAfterYieldStream(clock, 10.0, payload),
        )

    with _client(respond) as http:
        with pytest.raises(OsvUnavailableError):
            OsvClient(http, deadline=10.0, clock=clock).query_package("PyPI", "jinja2", "2.4.1")

    assert calls == 1
    assert timeouts
    assert all(0 < value <= 3.0 for value in timeouts[0].values())
