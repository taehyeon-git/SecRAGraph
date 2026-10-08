"""ASGI middleware enforcing bounded request bodies before multipart parsing."""

from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from security_review.api.errors import ErrorResponse


def correlation_id(value: str | None) -> str:
    """Normalize a caller-provided UUID or create a new correlation ID."""

    if value is not None:
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return str(uuid4())


def _header(scope: Scope, name: bytes) -> str | None:
    headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


class RequestBodyLimitMiddleware:
    """Reject oversized fixed or chunked bodies before downstream parsing."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope: Scope, receive: Receive, send: Send, value: str) -> None:
        body = ErrorResponse(
            code="request_too_large",
            message="The request body exceeds the configured limit.",
            correlation_id=value,
        )
        response = JSONResponse(status_code=413, content=body.model_dump(mode="json"))
        response.headers["X-Correlation-ID"] = value
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        value = correlation_id(_header(scope, b"x-correlation-id"))
        state["correlation_id"] = value

        content_length = _header(scope, b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = 0
            if declared_size > self.max_bytes:
                await self._reject(scope, receive, send, value)
                return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                buffered.append(message)
                break
            total += len(message.get("body", b""))
            if total > self.max_bytes:
                await self._reject(scope, receive, send, value)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        position = 0

        async def replay() -> Message:
            nonlocal position
            if position < len(buffered):
                message = buffered[position]
                position += 1
                return message
            return await receive()

        await self.app(scope, replay, send)
