"""Single-user bearer gate for locally served API routes."""

from __future__ import annotations

from hashlib import sha256
from hmac import compare_digest
from typing import cast

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from security_review.api.errors import ErrorResponse
from security_review.api.middleware import correlation_id


class ApiTokenMiddleware:
    """Reject unauthenticated /v1 requests before reading upload bodies."""

    def __init__(self, app: ASGIApp, token: str | None) -> None:
        self.app = app
        self._expected = sha256(token.encode("utf-8")).digest() if token is not None else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self._expected is None:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not isinstance(path, str) or not path.startswith("/v1/"):
            await self.app(scope, receive, send)
            return

        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        values = [value for key, value in headers if key.lower() == b"authorization"]
        candidate = values[0] if len(values) == 1 else b""
        provided = candidate[7:] if candidate.startswith(b"Bearer ") else b""
        authenticated = bool(provided) and compare_digest(sha256(provided).digest(), self._expected)
        if authenticated:
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        incoming_correlation = next(
            (
                value.decode("latin-1")
                for key, value in headers
                if key.lower() == b"x-correlation-id"
            ),
            None,
        )
        request_correlation_id = correlation_id(incoming_correlation)
        state["correlation_id"] = request_correlation_id
        response = JSONResponse(
            status_code=401,
            content=ErrorResponse(
                code="unauthorized",
                message="Authentication is required.",
                correlation_id=request_correlation_id,
            ).model_dump(mode="json"),
            headers={
                "WWW-Authenticate": "Bearer",
                "X-Correlation-ID": request_correlation_id,
            },
        )
        await response(scope, receive, send)
