"""Disposable API containing explicit passive and active DAST canaries."""

from __future__ import annotations

import os
import re
import sqlite3
from hmac import compare_digest
from threading import Lock
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from starlette.middleware.base import RequestResponseEndpoint

_TOKEN = os.environ.get("SECRAGRAPH_DAST_TEST_TOKEN")
if not _TOKEN:
    raise RuntimeError("A disposable DAST fixture token is required.")

app = FastAPI(
    title="SecRAGraph disposable DAST fixture",
    docs_url=None,
    redoc_url=None,
)
_counter_lock = Lock()
_public_requests = 0
_authenticated_protected_requests = 0
_host_redirect_requests = 0
_sql_vulnerable_mutations = 0
_sql_safe_mutations = 0
_ROUTES = (
    "/public",
    "/protected",
    "/sql-vulnerable",
    "/sql-safe",
    "/sql-numeric-vulnerable",
    "/sql-numeric-safe",
    "/redirect-vulnerable",
    "/redirect-safe",
)
_route_requests = {path: 0 for path in _ROUTES}
_attack_probes = {path: 0 for path in _ROUTES}
_SQLI_PROBE_PATTERN = re.compile(
    r"\b(?:or|and)\s+\S+\s*=\s*\S+|\bunion\s+(?:all\s+)?select\b|"
    r"\b(?:sleep|benchmark)\s*\(",
    flags=re.IGNORECASE | re.ASCII,
)


def _record_request(path: str, *, attack_probe: bool = False) -> None:
    """Keep bounded per-route proof counts, never request parameters."""

    with _counter_lock:
        _route_requests[path] += 1
        if attack_probe:
            _attack_probes[path] += 1


def _is_external_redirect_probe(value: str) -> bool:
    """Recognize absolute or scheme-relative redirect probes without storing them."""

    if value != value.strip():
        return False
    try:
        target = urlsplit(value)
        host = target.hostname
        _ = target.port  # Reject malformed ports and bracketed hosts.
    except ValueError:
        return False
    is_http = target.scheme.lower() in {"http", "https"}
    is_scheme_relative = not target.scheme and value.startswith("//")
    return bool(
        (is_http or is_scheme_relative)
        and target.netloc
        and host
        and host.rstrip(".").casefold() != "secragraph-target"
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host)
    )


@app.middleware("http")
async def add_nosniff_except_public(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Keep `/public` as the sole intentional missing-header canary."""

    response = await call_next(request)
    if request.url.path != "/public":
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/public")
def public() -> dict[str, bool]:
    """Intentionally omit X-Content-Type-Options for one passive ZAP alert."""

    global _public_requests
    _record_request("/public")
    with _counter_lock:
        _public_requests += 1
    return {"ok": True}


@app.get("/protected")
def protected(authorization: Annotated[str | None, Header()] = None) -> dict[str, bool]:
    """Count only requests that include the disposable session credential."""

    global _authenticated_protected_requests
    _record_request("/protected")
    if authorization is None or not compare_digest(authorization, f"Session {_TOKEN}"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    with _counter_lock:
        _authenticated_protected_requests += 1
    return {"ok": True}


def _sql_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE fixture_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO fixture_users (username) VALUES (?)", [("alice",), ("bob",)]
    )
    return connection


def _is_sqli_probe(value: str) -> bool:
    """Recognize SQL syntax probes without keeping their request values."""

    sample = value[:512]
    return any(token in sample for token in ("'", '"', "--", "/*", "*/", ";")) or bool(
        _SQLI_PROBE_PATTERN.search(sample)
    )


@app.get("/sql-vulnerable", openapi_extra={"x-secragraph-dast-active": True})
def sql_vulnerable(username: Annotated[str, Query(examples=["alice"])]) -> dict[str, int]:
    """Deliberately injectable SQLite query, confined to this disposable fixture."""

    global _sql_vulnerable_mutations
    attack_probe = _is_sqli_probe(username)
    _record_request("/sql-vulnerable", attack_probe=attack_probe)
    if attack_probe:
        with _counter_lock:
            _sql_vulnerable_mutations += 1
    connection = _sql_connection()
    try:
        # Intentional SQL injection canary; never copy this pattern into product code.
        query = f"SELECT username FROM fixture_users WHERE username = '{username}'"  # noqa: S608, E501  # nosec B608
        rows = connection.execute(query).fetchall()
        return {"matches": len(rows)}
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail="SQLite query error") from error
    finally:
        connection.close()


@app.get("/sql-safe", openapi_extra={"x-secragraph-dast-active": True})
def sql_safe(username: Annotated[str, Query(examples=["alice"])]) -> dict[str, int]:
    """Parameterized control with the same records and response shape."""

    global _sql_safe_mutations
    attack_probe = _is_sqli_probe(username)
    _record_request("/sql-safe", attack_probe=attack_probe)
    if attack_probe:
        with _counter_lock:
            _sql_safe_mutations += 1
    connection = _sql_connection()
    try:
        rows = connection.execute(
            "SELECT username FROM fixture_users WHERE username = ?", (username,)
        ).fetchall()
        return {"matches": len(rows)}
    finally:
        connection.close()


@app.get("/sql-numeric-vulnerable", openapi_extra={"x-secragraph-dast-active": True})
def sql_numeric_vulnerable(item_id: Annotated[str, Query(examples=["1"])]) -> dict[str, int]:
    """Deliberately interpolate a numeric parameter in this disposable canary."""

    _record_request("/sql-numeric-vulnerable", attack_probe=_is_sqli_probe(item_id))
    connection = _sql_connection()
    try:
        query = f"SELECT username FROM fixture_users WHERE id = {item_id}"  # noqa: S608  # nosec B608
        rows = connection.execute(query).fetchall()
        return {"matches": len(rows)}
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail="SQLite query error") from error
    finally:
        connection.close()


@app.get("/sql-numeric-safe", openapi_extra={"x-secragraph-dast-active": True})
def sql_numeric_safe(item_id: Annotated[str, Query(examples=["1"])]) -> dict[str, int]:
    """Validate the numeric value and bind it in the control query."""

    _record_request("/sql-numeric-safe", attack_probe=_is_sqli_probe(item_id))
    if not re.fullmatch(r"[0-9]{1,6}", item_id):
        raise HTTPException(status_code=422, detail="item_id must be numeric")
    connection = _sql_connection()
    try:
        rows = connection.execute(
            "SELECT username FROM fixture_users WHERE id = ?", (int(item_id),)
        ).fetchall()
        return {"matches": len(rows)}
    finally:
        connection.close()


@app.get("/redirect-vulnerable", openapi_extra={"x-secragraph-dast-active": True})
def redirect_vulnerable(next: Annotated[str, Query(examples=["/public"])]) -> RedirectResponse:
    """Deliberately follow an untrusted redirect target in this disposable canary."""

    _record_request("/redirect-vulnerable", attack_probe=_is_external_redirect_probe(next))
    return RedirectResponse(url=next, status_code=302)


@app.get("/redirect-safe", openapi_extra={"x-secragraph-dast-active": True})
def redirect_safe(next: Annotated[str, Query(examples=["/public"])]) -> RedirectResponse:
    """Ignore external targets; the only allowed destination is a local path."""

    _record_request("/redirect-safe", attack_probe=_is_external_redirect_probe(next))
    return RedirectResponse(url="/public", status_code=302)


@app.get("/stats", include_in_schema=False)
def stats() -> dict[str, int | dict[str, int]]:
    with _counter_lock:
        public_requests = _public_requests
        count = _authenticated_protected_requests
        redirects = _host_redirect_requests
        vulnerable_mutations = _sql_vulnerable_mutations
        safe_mutations = _sql_safe_mutations
        route_requests = _route_requests.copy()
        attack_probes = _attack_probes.copy()
    return {
        "public_requests": public_requests,
        "authenticated_protected_requests": count,
        "host_redirect_requests": redirects,
        "sql_vulnerable_mutations": vulnerable_mutations,
        "sql_safe_mutations": safe_mutations,
        "route_requests": route_requests,
        "attack_probes": attack_probes,
    }


@app.get("/host-redirect", include_in_schema=False)
def host_redirect(to: str) -> RedirectResponse:
    """CI-only network probe: issue a redirect to its short-lived host marker."""

    global _host_redirect_requests
    with _counter_lock:
        _host_redirect_requests += 1
    return RedirectResponse(url=to, status_code=302)
