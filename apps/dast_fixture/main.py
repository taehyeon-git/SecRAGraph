"""Small disposable API used only for authenticated passive DAST evidence."""

from __future__ import annotations

import os
from hmac import compare_digest
from threading import Lock
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException

_TOKEN = os.environ.get("SECRAGRAPH_DAST_TEST_TOKEN")
if not _TOKEN:
    raise RuntimeError("A disposable DAST fixture token is required.")

app = FastAPI(
    title="SecRAGraph disposable DAST fixture",
    docs_url=None,
    redoc_url=None,
)
_counter_lock = Lock()
_authenticated_protected_requests = 0


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/public")
def public() -> dict[str, bool]:
    """Intentionally omit X-Content-Type-Options for one passive ZAP alert."""

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
        count = _authenticated_protected_requests
    return {"authenticated_protected_requests": count}
