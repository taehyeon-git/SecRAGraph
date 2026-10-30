"""Disposable API containing explicit passive and active DAST canaries."""

from __future__ import annotations

import os
import re
import sqlite3
from hmac import compare_digest
from threading import Lock
from typing import Annotated

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
_SQLI_PROBE_PATTERN = re.compile(
    r"\b(?:or|and)\s+\S+\s*=\s*\S+|\bunion\s+(?:all\s+)?select\b|"
    r"\b(?:sleep|benchmark)\s*\(",
    flags=re.IGNORECASE | re.ASCII,
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
    with _counter_lock:
        _public_requests += 1
    return {"ok": True}


@app.get("/protected")
def protected(authorization: Annotated[str | None, Header()] = None) -> dict[str, bool]:
    """Count only requests that include the disposable session credential."""

    global _authenticated_protected_requests
    if authorization is None or not compare_digest(authorization, f"Session {_TOKEN}"):
        raise HTTPException(status_code=401, detail="Authentication required.")
    with _counter_lock:
        _authenticated_protected_requests += 1
    return {"ok": True}


def _sql_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE fixture_users (username TEXT NOT NULL)")
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
    if _is_sqli_probe(username):
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
    if _is_sqli_probe(username):
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


@app.get("/stats", include_in_schema=False)
def stats() -> dict[str, int]:
    with _counter_lock:
        public_requests = _public_requests
        count = _authenticated_protected_requests
        redirects = _host_redirect_requests
        vulnerable_mutations = _sql_vulnerable_mutations
        safe_mutations = _sql_safe_mutations
    return {
        "public_requests": public_requests,
        "authenticated_protected_requests": count,
        "host_redirect_requests": redirects,
        "sql_vulnerable_mutations": vulnerable_mutations,
        "sql_safe_mutations": safe_mutations,
    }


@app.get("/host-redirect", include_in_schema=False)
def host_redirect(to: str) -> RedirectResponse:
    """CI-only network probe: issue a redirect to its short-lived host marker."""

    global _host_redirect_requests
    with _counter_lock:
        _host_redirect_requests += 1
    return RedirectResponse(url=to, status_code=302)
