"""Local member registration, login, identity, and logout endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Protocol, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from security_review.api.dependencies import get_principal, get_settings
from security_review.api.errors import APIError
from security_review.api.member_auth import Principal
from security_review.config import Settings
from security_review.membership.service import MembershipError

router = APIRouter(prefix="/v1/auth", tags=["members"])


class MemberIdentityLike(Protocol):
    @property
    def user_id(self) -> UUID: ...

    @property
    def username(self) -> str: ...


class LoginResultLike(Protocol):
    @property
    def token(self) -> str: ...

    @property
    def identity(self) -> MemberIdentityLike: ...

    @property
    def expires_at(self) -> datetime: ...


class MembershipManager(Protocol):
    def register(self, username: str, password: str) -> MemberIdentityLike: ...

    def login(self, username: str, password: str) -> LoginResultLike: ...

    def resolve(self, token: str) -> MemberIdentityLike | None: ...

    def logout(self, token: str) -> None: ...


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=1_024)


class MemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    username: str


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    username: str
    expires_at: datetime


def get_membership_service(request: Request) -> MembershipManager:
    service = getattr(request.app.state, "membership_service", None)
    if service is None:
        raise APIError(503, "membership_unavailable", "Member login is unavailable.")
    return cast(MembershipManager, service)


@router.post("/register", response_model=MemberResponse, status_code=201)
def register(
    credentials: Credentials,
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    membership: Annotated[MembershipManager, Depends(get_membership_service)],
) -> MemberResponse:
    """Create a local member only when development self-registration is enabled."""

    response.headers["Cache-Control"] = "no-store"
    if settings.environment != "development" or not settings.allow_self_registration:
        raise APIError(403, "registration_disabled", "Self-registration is disabled.")
    try:
        identity = membership.register(credentials.username, credentials.password)
    except MembershipError as error:
        if error.code in {"username_taken", "invalid_input"}:
            raise APIError(
                422, "registration_failed", "The account could not be created."
            ) from error
        raise
    return MemberResponse(user_id=identity.user_id, username=identity.username)


@router.post("/login", response_model=LoginResponse)
def login(
    credentials: Credentials,
    response: Response,
    membership: Annotated[MembershipManager, Depends(get_membership_service)],
) -> LoginResponse:
    """Exchange credentials for an opaque, expiring member session."""

    response.headers["Cache-Control"] = "no-store"
    try:
        result = membership.login(credentials.username, credentials.password)
    except MembershipError as error:
        if error.code in {"invalid_credentials", "locked", "disabled", "invalid_input"}:
            raise APIError(401, "invalid_credentials", "The credentials are invalid.") from error
        raise
    return LoginResponse(
        token=result.token, username=result.identity.username, expires_at=result.expires_at
    )


@router.get("/me", response_model=MemberResponse)
def me(
    response: Response,
    principal: Annotated[Principal, Depends(get_principal)],
) -> MemberResponse:
    """Return the identity associated with the current member session."""

    if principal.kind != "member" or principal.member_id is None or principal.username is None:
        raise APIError(401, "unauthorized", "A member session is required.")
    response.headers["Cache-Control"] = "no-store"
    return MemberResponse(user_id=principal.member_id, username=principal.username)


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    principal: Annotated[Principal, Depends(get_principal)],
    membership: Annotated[MembershipManager, Depends(get_membership_service)],
) -> Response:
    """Revoke the presented member session."""

    if principal.kind != "member":
        raise APIError(401, "unauthorized", "A member session is required.")
    header = request.headers.get("Authorization", "")
    if not header.startswith("Session "):
        raise APIError(401, "unauthorized", "A member session is required.")
    membership.logout(header[len("Session ") :])
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
