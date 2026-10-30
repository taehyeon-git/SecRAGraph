"""Untrusted OpenAPI and ZAP report normalization."""

from __future__ import annotations

import json
from time import monotonic

import pytest

from security_review.dast import zap
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


def test_active_openapi_imports_only_explicitly_marked_get_routes() -> None:
    schema = json.loads(_schema())
    schema["paths"]["/public"]["get"]["x-secragraph-dast-active"] = True
    schema["paths"]["/protected"]["get"]["x-secragraph-dast-active"] = "true"
    schema["paths"]["/items/{item_id}"]["get"]["x-secragraph-dast-active"] = False
    schema["paths"]["/public"]["head"] = {"x-secragraph-dast-active": True}

    safe = sanitize_openapi(json.dumps(schema).encode(), origin=ORIGIN, active=True)
    payload = json.loads(safe.document)

    assert safe.eligible_endpoints == ("GET /public",)
    assert list(payload["paths"]) == ["/public"]
    assert list(payload["paths"]["/public"]) == ["get"]


def test_active_openapi_requires_marked_get_route() -> None:
    with pytest.raises(DastInputError, match="no_active_openapi_operations"):
        sanitize_openapi(_schema(), origin=ORIGIN, active=True)


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
        b"not-json",
        b"{}",
        b'{"site":[]}',
        b"x" * 8_000_001,
    ],
    ids=[
        "off-origin",
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


def test_passive_report_omits_same_origin_alerts_outside_openapi_routes() -> None:
    payload = json.loads(_report())
    payload["site"][0]["alerts"][0]["instances"].append(
        {"uri": f"{ORIGIN}/unlisted?token=secret-value", "method": "GET"}
    )
    findings = parse_zap_report(
        json.dumps(payload).encode(),
        origin=ORIGIN,
        eligible_endpoints=("GET /items/{item_id}",),
    )
    assert len(findings) == 1
    assert findings[0].http_path == "/items/{item_id}"
    assert "secret-value" not in findings[0].model_dump_json()


def test_active_report_omits_same_origin_alerts_outside_marked_seeds() -> None:
    payload = json.loads(_report())
    instances = payload["site"][0]["alerts"][0]["instances"]
    instances.extend(
        [
            {"uri": f"{ORIGIN}/", "method": "GET", "evidence": "private-root"},
            {"uri": f"{ORIGIN}/items/123/", "method": "GET"},
            {"uri": f"{ORIGIN}/unlisted?token=secret-value", "method": "GET"},
        ]
    )
    findings = parse_zap_report(
        json.dumps(payload).encode(),
        origin=ORIGIN,
        eligible_endpoints=("GET /items/{item_id}",),
        active=True,
    )
    assert len(findings) == 1
    assert findings[0].http_path == "/items/{item_id}"
    assert "secret-value" not in findings[0].model_dump_json()


@pytest.mark.parametrize(
    ("uri", "method"),
    [
        ("http://outside.example/unlisted", "GET"),
        (f"{ORIGIN}/unlisted", "POST"),
        (42, "GET"),
    ],
)
def test_active_report_still_rejects_off_origin_or_malformed_instances(
    uri: object, method: str
) -> None:
    payload = json.loads(_report())
    payload["site"][0]["alerts"][0]["instances"] = [{"uri": uri, "method": method}]
    with pytest.raises(DastReportError):
        parse_zap_report(
            json.dumps(payload).encode(),
            origin=ORIGIN,
            eligible_endpoints=("GET /items/{item_id}",),
            active=True,
        )


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


def test_zap_report_reuses_route_matching_for_repeated_instances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoints = tuple(f"GET /route-{index:04d}" for index in range(999)) + ("GET /item/{item_id}",)
    instance = {"uri": f"{ORIGIN}/item/secret", "method": "GET"}
    report = {
        "site": [
            {
                "@name": ORIGIN,
                "alerts": [
                    {
                        "pluginid": "10021",
                        "riskcode": "1",
                        "confidence": "2",
                        "instances": [instance] * 1_000,
                    }
                ],
            }
        ]
    }
    route_checks = 0
    original = zap._route_matches

    def count_checks(route: str, actual: str) -> bool:
        nonlocal route_checks
        route_checks += 1
        if route_checks > 3_000:
            pytest.fail("Repeated identical instances rematched every eligible route")
        return original(route, actual)

    monkeypatch.setattr(zap, "_route_matches", count_checks)
    findings = parse_zap_report(
        json.dumps(report).encode(), origin=ORIGIN, eligible_endpoints=endpoints
    )

    assert len(findings) == 1
    assert findings[0].http_path == "/item/{item_id}"
    assert route_checks <= 3_000


def test_zap_report_prefers_literal_route_over_parameter_route() -> None:
    payload = json.loads(_report(f"{ORIGIN}/items/specific"))
    payload["site"][0]["alerts"][0]["instances"] = payload["site"][0]["alerts"][0]["instances"][:1]
    findings = parse_zap_report(
        json.dumps(payload).encode(),
        origin=ORIGIN,
        eligible_endpoints=("GET /items/{item_id}", "GET /items/specific"),
    )

    assert len(findings) == 1
    assert findings[0].http_path == "/items/specific"


def test_zap_report_respects_parse_deadline() -> None:
    with pytest.raises(DastReportError, match="zap_report_timeout"):
        parse_zap_report(
            _report(),
            origin=ORIGIN,
            eligible_endpoints=("GET /items/{item_id}",),
            deadline=monotonic() - 1,
        )
