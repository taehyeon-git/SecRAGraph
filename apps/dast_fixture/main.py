"""Small disposable API used only for authenticated passive DAST evidence."""

from __future__ import annotations

import os
from hmac import compare_digest
from threading import Lock
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request, Response
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


@app.get("/stats", include_in_schema=False)
def stats() -> dict[str, int]:
    with _counter_lock:
        public_requests = _public_requests
        count = _authenticated_protected_requests
        redirects = _host_redirect_requests
    return {
        "public_requests": public_requests,
        "authenticated_protected_requests": count,
        "host_redirect_requests": redirects,
    }


@app.get("/host-redirect", include_in_schema=False)
def host_redirect(to: str) -> RedirectResponse:
    """CI-only network probe: issue a redirect to its short-lived host marker."""

    global _host_redirect_requests
    with _counter_lock:
        _host_redirect_requests += 1
    return RedirectResponse(url=to, status_code=302)
