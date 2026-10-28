"""The disposable DAST target exposes only bounded GET operations."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[3]


def test_fixture_compose_is_disposable_internal_and_not_published() -> None:
    compose = yaml.safe_load((ROOT / "infra/dast/compose.yaml").read_text(encoding="utf-8"))
    target = compose["services"]["target"]
    assert target["labels"]["io.secragraph.dast.disposable"] == "true"
    assert "ports" not in target
    assert target["read_only"] is True
    assert target["cap_drop"] == ["ALL"]
    assert compose["networks"]["fixture"]["internal"] is True


def test_fixture_has_one_missing_header_alert_and_authenticated_route(monkeypatch) -> None:
    monkeypatch.setenv("SECRAGRAPH_DAST_TEST_TOKEN", "fixture-secret")
    module = importlib.import_module("apps.dast_fixture.main")
    module = importlib.reload(module)

    schema = module.app.openapi()
    assert set(schema["paths"]) == {"/public", "/protected"}
    assert all(set(operations) == {"get"} for operations in schema["paths"].values())

    assert module.public() == {"ok": True}
    with pytest.raises(HTTPException) as missing:
        module.protected(None)
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong:
        module.protected("Session wrong")
    assert wrong.value.status_code == 401
    assert module.stats()["authenticated_protected_requests"] == 0

    assert module.protected("Session fixture-secret") == {"ok": True}
    assert module.stats()["authenticated_protected_requests"] == 1
