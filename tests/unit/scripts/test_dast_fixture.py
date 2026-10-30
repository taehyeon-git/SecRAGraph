"""The disposable DAST target exposes only bounded GET operations."""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException
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
    assert set(schema["paths"]) == {"/public", "/protected", "/sql-vulnerable", "/sql-safe"}
    assert all(set(operations) == {"get"} for operations in schema["paths"].values())
    assert schema["paths"]["/sql-vulnerable"]["get"]["x-secragraph-dast-active"] is True
    assert schema["paths"]["/sql-safe"]["get"]["x-secragraph-dast-active"] is True
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
    attack = "alice' OR '1'='1"
    assert module.sql_vulnerable(attack)["matches"] > 1
    assert module.sql_safe(attack) == {"matches": 0}
    assert module.stats()["sql_vulnerable_mutations"] >= 1
    assert module.stats()["sql_safe_mutations"] >= 1
    assert attack not in repr(module.stats())


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
