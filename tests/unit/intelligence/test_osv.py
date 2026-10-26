"""Bounded, offline OSV package/version CVE evidence tests."""

from __future__ import annotations

import json

import httpx
import pytest

from security_review.intelligence.osv import OsvClient, OsvInputError, OsvUnavailableError


def _advisory(*, identifier: str = "GHSA-abcd-1234-5678", aliases=None, withdrawn=None):
    return {
        "id": identifier,
        "aliases": aliases if aliases is not None else ["CVE-2024-12345"],
        "summary": "Template processing issue",
        "published": "2024-01-01T00:00:00Z",
        "withdrawn": withdrawn,
        "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"}}],
    }


def _client(handler):
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
