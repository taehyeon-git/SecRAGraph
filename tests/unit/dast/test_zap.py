"""Untrusted OpenAPI and ZAP report normalization."""

from __future__ import annotations

import json

import pytest

from security_review.dast.zap import (
    DastInputError,
    DastReportError,
    parse_zap_report,
    sanitize_openapi,
)

ORIGIN = "http://secragraph-target:8765"


def _schema(**extra: object) -> bytes:
    payload: dict[str, object] = {
        "openapi": "3.1.0",
        "info": {"title": "Disposable API", "version": "1"},
        "servers": [{"url": "https://outside.example/api"}],
        "paths": {
            "/public": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/protected": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {"responses": {"201": {"description": "created"}}},
            },
            "/items/{item_id}": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "delete": {"responses": {"204": {"description": "deleted"}}},
            },
        },
    }
    payload.update(extra)
    return json.dumps(payload).encode()


def _report(uri: str = f"{ORIGIN}/items/secret-value?token=secret-value") -> bytes:
    return json.dumps(
        {
            "@version": "2.17.0",
            "site": [
                {
                    "@name": ORIGIN,
                    "alerts": [
                        {
                            "pluginid": "10021",
                            "riskcode": "2",
                            "confidence": "2",
                            "cweid": "693",
                            "name": "Do not copy secret-value into the report",
                            "solution": "secret-value",
                            "instances": [
                                {
                                    "uri": uri,
                                    "method": "GET",
                                    "evidence": "secret-value",
                                    "attack": "secret-value",
                                    "requestHeader": "Authorization: secret-value",
                                },
                                {
                                    "uri": f"{ORIGIN}/items/another-id",
                                    "method": "GET",
                                },
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def test_sanitize_openapi_removes_mutations_and_overrides_external_server() -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    payload = json.loads(safe.document)

    assert payload["servers"] == [{"url": ORIGIN}]
    assert "post" not in payload["paths"]["/protected"]
    assert "delete" not in payload["paths"]["/items/{item_id}"]
    assert safe.eligible_endpoints == (
        "GET /items/{item_id}",
        "GET /protected",
        "GET /public",
    )


@pytest.mark.parametrize(
    "payload",
    [
        _schema(components={"schemas": {"X": {"$ref": "https://evil.test/schema"}}}),
        _schema(
            paths={
                "/public": {
                    "servers": [{"url": "https://outside.example"}],
                    "get": {"responses": {}},
                }
            }
        ),
        _schema(
            paths={
                "/public": {
                    "get": {"servers": [{"url": "https://outside.example"}], "responses": {}}
                }
            }
        ),
        _schema(components={"links": {"Next": {"server": {"url": "https://outside.example"}}}}),
        _schema(paths={"/mutate": {"post": {"responses": {}}}}),
        _schema(paths={"//evil": {"get": {"responses": {}}}}),
        _schema(openapi="2.0"),
        b"not-json",
    ],
)
def test_sanitize_openapi_rejects_unsafe_or_unusable_schema(payload: bytes) -> None:
    with pytest.raises(DastInputError):
        sanitize_openapi(payload, origin=ORIGIN)


def test_sanitize_openapi_rejects_deeply_nested_json_as_input_error() -> None:
    nested = b"[" * 1_100 + b"0" + b"]" * 1_100
    raw = (
        b'{"openapi":"3.1.0","info":{},"paths":{"/public":{"get":{"responses":{}}}},'
        b'"components":{"nested":' + nested + b"}}"
    )

    with pytest.raises(DastInputError, match="invalid_openapi_json"):
        sanitize_openapi(raw, origin=ORIGIN)


def test_sanitize_openapi_rejects_valid_but_excessively_deep_schema() -> None:
    nested = b"[" * 150 + b"0" + b"]" * 150
    raw = (
        b'{"openapi":"3.1.0","info":{},"paths":{"/public":{"get":{"responses":{}}}},'
        b'"components":{"nested":' + nested + b"}}"
    )

    with pytest.raises(DastInputError, match="openapi_too_complex"):
        sanitize_openapi(raw, origin=ORIGIN)


def test_zap_report_uses_route_template_and_discards_secrets() -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    findings = parse_zap_report(
        _report(), origin=ORIGIN, eligible_endpoints=safe.eligible_endpoints
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "ZAP/10021"
    assert finding.http_method == "GET"
    assert finding.http_path == "/items/{item_id}"
    assert finding.file_path is None
    assert finding.line_start is None
    assert finding.cwe_ids == ("CWE-693",)
    assert "secret-value" not in finding.model_dump_json()


@pytest.mark.parametrize(
    "raw",
    [
        _report("http://outside.example/items/123"),
        _report(f"{ORIGIN}/unlisted"),
        b"not-json",
        b"{}",
        b'{"site":[]}',
        b"x" * 8_000_001,
    ],
    ids=[
        "off-origin",
        "unlisted-route",
        "invalid-json",
        "missing-site",
        "empty-site",
        "oversized",
    ],
)
def test_zap_report_rejects_off_scope_or_malformed_output(raw: bytes) -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    with pytest.raises(DastReportError):
        parse_zap_report(raw, origin=ORIGIN, eligible_endpoints=safe.eligible_endpoints)


def test_zap_report_rejects_deeply_nested_json_as_report_error() -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    raw = b'{"site":' + b"[" * 1_100 + b"0" + b"]" * 1_100 + b"}"

    with pytest.raises(DastReportError, match="invalid_zap_json"):
        parse_zap_report(raw, origin=ORIGIN, eligible_endpoints=safe.eligible_endpoints)


def test_zap_report_rejects_unbounded_numeric_codes() -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    payload = json.loads(_report())
    payload["site"][0]["alerts"][0]["riskcode"] = "1" * 10_000

    with pytest.raises(DastReportError):
        parse_zap_report(
            json.dumps(payload).encode(),
            origin=ORIGIN,
            eligible_endpoints=safe.eligible_endpoints,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("site_name", None),
        ("site_name", 42),
        ("site_name", ORIGIN + "/" + "a" * 4_097),
        ("uri", ORIGIN + "/items/" + "a" * 4_097),
    ],
    ids=["null-site", "numeric-site", "long-site", "long-uri"],
)
def test_zap_report_rejects_invalid_url_fields(field: str, value: object) -> None:
    safe = sanitize_openapi(_schema(), origin=ORIGIN)
    payload = json.loads(_report())
    if field == "site_name":
        payload["site"][0]["@name"] = value
    else:
        payload["site"][0]["alerts"][0]["instances"][0]["uri"] = value

    with pytest.raises(DastReportError):
        parse_zap_report(
            json.dumps(payload).encode(),
            origin=ORIGIN,
            eligible_endpoints=safe.eligible_endpoints,
        )
