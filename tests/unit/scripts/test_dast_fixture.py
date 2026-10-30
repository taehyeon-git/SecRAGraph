"""The disposable DAST target exposes only bounded GET operations."""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import Response

ROOT = Path(__file__).resolve().parents[3]


def test_fixture_compose_is_disposable_internal_and_not_published() -> None:
    compose = yaml.safe_load((ROOT / "infra/dast/compose.yaml").read_text(encoding="utf-8"))
    target = compose["services"]["target"]
    assert target["labels"]["io.secragraph.dast.disposable"] == "true"
    assert target["labels"]["io.secragraph.dast.active-permitted"] == "true"
    assert "ports" not in target
    assert target["read_only"] is True
    assert target["cap_drop"] == ["ALL"]
    assert compose["networks"]["fixture"]["internal"] is True


def test_fixture_has_one_missing_header_alert_and_authenticated_route(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.import_module("apps.dast_fixture.main")
    module = importlib.reload(module)

    schema = module.app.openapi()
    assert set(schema["paths"]) == {
        "/public",
        "/protected",
        "/sql-vulnerable",
        "/sql-safe",
        "/sql-numeric-vulnerable",
        "/sql-numeric-safe",
        "/redirect-vulnerable",
        "/redirect-safe",
    }
    assert all(set(operations) == {"get"} for operations in schema["paths"].values())
    assert schema["paths"]["/sql-vulnerable"]["get"]["x-secragraph-dast-active"] is True
    assert schema["paths"]["/sql-safe"]["get"]["x-secragraph-dast-active"] is True
    for path in (
        "/sql-numeric-vulnerable",
        "/sql-numeric-safe",
        "/redirect-vulnerable",
        "/redirect-safe",
    ):
        assert schema["paths"][path]["get"]["x-secragraph-dast-active"] is True
    assert not schema["paths"]["/public"]["get"].get("x-secragraph-dast-active")

    assert module.public() == {"ok": True}
    assert module.stats()["public_requests"] == 1
    with pytest.raises(HTTPException) as missing:
        module.protected(None)
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong:
        module.protected("Session wrong")
    assert wrong.value.status_code == 401
    assert module.stats()["authenticated_protected_requests"] == 0

    assert module.protected("Session fixture-secret") == {"ok": True}
    assert module.stats()["authenticated_protected_requests"] == 1
    response = module.host_redirect("http://172.17.0.1:12345/marker")
    assert response.status_code == 302
    assert response.headers["location"] == "http://172.17.0.1:12345/marker"
    assert module.stats()["host_redirect_requests"] == 1


def test_sql_canary_exposes_vulnerability_and_safe_control_without_payload_logs(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert module.sql_vulnerable("alice") == {"matches": 1}
    assert module.sql_safe("alice") == {"matches": 1}
    assert module.sql_vulnerable("bob") == {"matches": 1}
    assert module.sql_safe("bob") == {"matches": 1}
    assert module.sql_vulnerable("") == {"matches": 0}
    assert module.sql_safe("") == {"matches": 0}
    assert module.stats()["sql_vulnerable_mutations"] == 0
    assert module.stats()["sql_safe_mutations"] == 0
    attack = "alice' OR '1'='1"
    assert module.sql_vulnerable(attack)["matches"] > 1
    assert module.sql_safe(attack) == {"matches": 0}
    assert module.stats()["sql_vulnerable_mutations"] >= 1
    assert module.stats()["sql_safe_mutations"] >= 1
    assert attack not in repr(module.stats())


@pytest.mark.parametrize("probe", ["'", '"', "1 OR 1=1", "1 UNION SELECT 1", "1--", "1/*x*/"])
def test_sql_probe_classifier_accepts_common_injection_shapes(monkeypatch, probe: str) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))
    assert module._is_sqli_probe(probe)
    assert not module._is_sqli_probe("bob")


def test_numeric_sql_canary_and_validated_control(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert module.sql_numeric_vulnerable("1") == {"matches": 1}
    assert module.sql_numeric_safe("1") == {"matches": 1}
    assert module.sql_numeric_vulnerable("1 OR 1=1") == {"matches": 2}
    with pytest.raises(HTTPException) as rejected:
        module.sql_numeric_safe("1 OR 1=1")
    assert rejected.value.status_code == 422
    assert module.stats()["attack_probes"]["/sql-numeric-vulnerable"] == 1
    assert module.stats()["attack_probes"]["/sql-numeric-safe"] == 1


def test_external_redirect_canary_and_local_control(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert module.redirect_vulnerable("/public").headers["location"] == "/public"
    assert module.redirect_safe("/public").headers["location"] == "/public"
    untrusted = "https://example.invalid/marker"
    assert module.redirect_vulnerable(untrusted).headers["location"] == untrusted
    assert module.redirect_safe(untrusted).headers["location"] == "/public"
    assert module.stats()["attack_probes"]["/redirect-vulnerable"] == 1
    assert module.stats()["attack_probes"]["/redirect-safe"] == 1
    assert untrusted not in repr(module.stats())


@pytest.mark.parametrize(
    "candidate",
    ["/public", "http:relative", "https:///missing-host", "//", "//?next=elsewhere"],
)
def test_redirect_probe_excludes_local_or_hostless_references(monkeypatch, candidate: str) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert not module._is_external_redirect_probe(candidate)
    module.redirect_safe(candidate)
    assert module.stats()["attack_probes"]["/redirect-safe"] == 0


@pytest.mark.parametrize("candidate", ["https://example.invalid/path", "//example.invalid/path"])
def test_redirect_probe_accepts_hosted_http_references(monkeypatch, candidate: str) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert module._is_external_redirect_probe(candidate)
    module.redirect_safe(candidate)
    assert module.stats()["attack_probes"]["/redirect-safe"] == 1


@pytest.mark.parametrize(
    "candidate",
    [
        "http://secragraph-target:8000/public",
        "https://secragraph-target/public",
        "//secragraph-target:8000/public",
        "HTTP://SECRAGRAPH-TARGET.:8000/public",
        "http://user@secragraph-target:8000/public",
    ],
)
def test_redirect_probe_excludes_fixture_origin(monkeypatch, candidate: str) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    assert not module._is_external_redirect_probe(candidate)
    module.redirect_safe(candidate)
    assert module.stats()["attack_probes"]["/redirect-safe"] == 0


def test_manifest_covers_equal_vulnerable_and_benign_cases_by_rule() -> None:
    manifest = json.loads((ROOT / "data/evaluation/dast_cases.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    assert manifest["schema_version"] == 1
    assert manifest["provenance"] == "author-written-synthetic"
    assert len(cases) == 8
    assert len({case["id"] for case in cases}) == 8
    assert (
        len({(case["mode"], case["rule_id"], case["method"], case["path"]) for case in cases}) == 8
    )
    for rule, count in (("ZAP/40018", 4), ("ZAP/20019", 2), ("ZAP/10021", 2)):
        selected = [case for case in cases if case["rule_id"] == rule]
        assert len(selected) == count
        assert sum(case["expected"] for case in selected) == count // 2
    assert all(
        case["proof"] == ("attack_probe" if case["mode"] == "active" else "route_request")
        for case in cases
    )


@pytest.mark.skipif(sys.platform == "win32", reason="ASGI middleware call hangs on Windows")
def test_http_routes_expose_oracle_behavior_and_counts(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.reload(importlib.import_module("apps.dast_fixture.main"))

    async def exercise() -> None:
        async with AsyncClient(
            transport=ASGITransport(app=module.app), base_url="http://fixture"
        ) as client:
            public = await client.get("/public")
            protected = await client.get(
                "/protected", headers={"Authorization": "Session fixture-secret"}
            )
            numeric_bad = await client.get(
                "/sql-numeric-vulnerable", params={"item_id": "1 OR 1=1"}
            )
            numeric_safe = await client.get("/sql-numeric-safe", params={"item_id": "1 OR 1=1"})
            redirect_bad = await client.get(
                "/redirect-vulnerable",
                params={"next": "https://example.invalid/marker"},
                follow_redirects=False,
            )
            redirect_safe = await client.get(
                "/redirect-safe",
                params={"next": "https://example.invalid/marker"},
                follow_redirects=False,
            )
        assert "x-content-type-options" not in public.headers
        assert protected.headers["x-content-type-options"] == "nosniff"
        assert numeric_bad.json() == {"matches": 2}
        assert numeric_safe.status_code == 422
        assert redirect_bad.headers["location"] == "https://example.invalid/marker"
        assert redirect_safe.headers["location"] == "/public"

    asyncio.run(exercise())
    counts = module.stats()
    for path in (
        "/public",
        "/protected",
        "/sql-numeric-vulnerable",
        "/sql-numeric-safe",
        "/redirect-vulnerable",
        "/redirect-safe",
    ):
        assert counts["route_requests"][path] >= 1


@pytest.mark.skipif(sys.platform == "win32", reason="ASGI middleware call hangs on Windows")
def test_only_public_response_omits_nosniff_header(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.import_module("apps.dast_fixture.main")
    module = importlib.reload(module)

    async def response_for(path: str, status_code: int) -> Response:
        request = Request(
            {"type": "http", "method": "GET", "path": path, "headers": [], "server": ("test", 80)}
        )

        async def call_next(_request: Request) -> Response:
            return Response(status_code=status_code)

        return await module.add_nosniff_except_public(request, call_next)

    public = asyncio.run(response_for("/public", 200))
    protected_ok = asyncio.run(response_for("/protected", 200))
    protected_unauthorized = asyncio.run(response_for("/protected", 401))

    assert "x-content-type-options" not in public.headers
    assert protected_ok.headers["x-content-type-options"] == "nosniff"
    assert protected_unauthorized.headers["x-content-type-options"] == "nosniff"
