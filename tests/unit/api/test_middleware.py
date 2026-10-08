from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from security_review.api.middleware import RequestBodyLimitMiddleware

ASGIMessage = dict[str, Any]


def run_asgi(
    middleware: RequestBodyLimitMiddleware,
    messages: list[ASGIMessage],
) -> tuple[list[ASGIMessage], list[bytes]]:
    sent: list[ASGIMessage] = []
    downstream_bodies: list[bytes] = []
    iterator = iter(messages)

    async def receive() -> ASGIMessage:
        return next(iterator)

    async def send(message: ASGIMessage) -> None:
        sent.append(message)

    async def downstream(
        scope: ASGIMessage,
        receive_body: Callable[[], Awaitable[ASGIMessage]],
        send_response: Callable[[ASGIMessage], Awaitable[None]],
    ) -> None:
        del scope
        while True:
            message = await receive_body()
            downstream_bodies.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send_response({"type": "http.response.start", "status": 204, "headers": []})
        await send_response({"type": "http.response.body", "body": b""})

    middleware.app = downstream
    scope: ASGIMessage = {
        "type": "http",
        "method": "POST",
        "path": "/upload",
        "headers": [],
        "state": {},
    }
    asyncio.run(middleware(scope, receive, send))
    return sent, downstream_bodies


def test_chunked_body_over_limit_is_rejected_before_downstream() -> None:
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=5)  # type: ignore[arg-type]

    sent, downstream_bodies = run_asgi(
        middleware,
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        ],
    )

    assert downstream_bodies == []
    assert sent[0]["status"] == 413
    body = json.loads(sent[1]["body"])
    assert body["code"] == "request_too_large"
    assert body["correlation_id"] != "unavailable"


def test_body_within_limit_is_replayed_unchanged() -> None:
    middleware = RequestBodyLimitMiddleware(lambda *_: None, max_bytes=6)  # type: ignore[arg-type]

    sent, downstream_bodies = run_asgi(
        middleware,
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        ],
    )

    assert downstream_bodies == [b"123", b"456"]
    assert sent[0]["status"] == 204
