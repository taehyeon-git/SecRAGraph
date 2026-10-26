"""Early ASGI authentication for operator and local-member credentials."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from typing import Literal, Protocol, cast
from uuid import UUID

from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

from security_review.api.errors import ErrorResponse
from security_review.api.middleware import correlation_id


class MemberIdentityLike(Protocol):
    @property
    def user_id(self) -> UUID: ...

    @property
    def username(self) -> str: ...


class MemberResolver(Protocol):
    def resolve(self, token: str) -> MemberIdentityLike | None: ...


@dataclass(frozen=True)
class Principal:
    kind: Literal["service", "member"]
    member_id: UUID | None = None
    username: str | None = None


class MemberAuthMiddleware:
    """Reject unauthorized API requests before multipart bodies are buffered."""

    def __init__(
        self,
        app: ASGIApp,
        token: str | None,
        *,
        membership: MemberResolver | None = None,
        allow_anonymous: bool = False,
    ) -> None:
        self.app = app
        self._expected = sha256(token.encode("utf-8")).digest() if token is not None else None
        self._membership = membership
        self._allow_anonymous = allow_anonymous

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not isinstance(path, str) or not path.startswith("/v1/"):
            await self.app(scope, receive, send)
            return

        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        values = [value for key, value in headers if key.lower() == b"authorization"]
        if (
            not values
            and path in {"/v1/auth/login", "/v1/auth/register"}
            and scope.get("method") == "POST"
        ):
            await self.app(scope, receive, send)
            return
        if not values and self._allow_anonymous:
            scope.setdefault("state", {})["principal"] = Principal(kind="service")
            await self.app(scope, receive, send)
            return
        if len(values) != 1:
            await self._reject(scope, receive, send)
            return

        value = values[0]
        if (
            len(value) > 2_048
            or value.count(b" ") != 1
            or any(byte < 32 or byte > 126 or byte == 44 for byte in value)
        ):
            await self._reject(scope, receive, send)
            return
        if value.startswith(b"Bearer ") and self._expected is not None:
            provided = value[len(b"Bearer ") :]
            if provided and compare_digest(sha256(provided).digest(), self._expected):
                scope.setdefault("state", {})["principal"] = Principal(kind="service")
                await self.app(scope, receive, send)
                return
        elif value.startswith(b"Session ") and self._membership is not None:
            provided = value[len(b"Session ") :]
            if provided:
                try:
                    identity = await run_in_threadpool(
                        self._membership.resolve, provided.decode("ascii")
                    )
                except Exception:  # Persistence failures must fail closed before reading uploads.
                    await self._reject(scope, receive, send, unavailable=True)
                    return
                if identity is not None:
                    scope.setdefault("state", {})["principal"] = Principal(
                        kind="member", member_id=identity.user_id, username=identity.username
                    )
                    await self.app(scope, receive, send)
                    return
        await self._reject(scope, receive, send)

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send, *, unavailable: bool = False
    ) -> None:
        headers = cast(list[tuple[bytes, bytes]], scope.get("headers", []))
        incoming = next(
            (
                value.decode("latin-1")
                for key, value in headers
                if key.lower() == b"x-correlation-id"
            ),
            None,
        )
        request_id = correlation_id(incoming)
        scope.setdefault("state", {})["correlation_id"] = request_id
        response = JSONResponse(
            status_code=503 if unavailable else 401,
            content=ErrorResponse(
                code="dependency_unavailable" if unavailable else "unauthorized",
                message=(
                    "An authentication dependency is unavailable."
                    if unavailable
                    else "Authentication is required."
                ),
                correlation_id=request_id,
            ).model_dump(mode="json"),
            headers={
                "WWW-Authenticate": "Bearer, Session",
                "X-Correlation-ID": request_id,
                "Cache-Control": "no-store",
            },
        )
        await response(scope, receive, send)
