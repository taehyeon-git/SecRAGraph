"""Stable API errors that never expose internal exception text."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException

from security_review.ports import ReportRepositoryError


class ErrorResponse(BaseModel):
    """Public error envelope returned by every API failure path."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    correlation_id: str
    details: Any | None = None


class APIError(Exception):
    """Typed expected failure mapped to a public status and error code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any | None = None,
    ) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def _correlation_id(request: Request) -> str:
    return str(getattr(request.state, "correlation_id", "unavailable"))


def _response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: Any | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        code=code,
        message=message,
        correlation_id=_correlation_id(request),
        details=details,
    )
    response = JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))
    response.headers["X-Correlation-ID"] = body.correlation_id
    return response


async def api_error_handler(request: Request, error: APIError) -> JSONResponse:
    return _response(
        request,
        status_code=error.status_code,
        code=error.code,
        message=error.message,
        details=error.details,
    )


async def validation_error_handler(
    request: Request,
    error: RequestValidationError,
) -> JSONResponse:
    details = [
        {
            "type": item.get("type", "validation_error"),
            "location": list(item.get("loc", ())),
            "message": item.get("msg", "Invalid request."),
        }
        for item in error.errors()
    ]
    return _response(
        request,
        status_code=422,
        code="validation_error",
        message="Request validation failed.",
        details=details,
    )


async def http_error_handler(
    request: Request,
    error: StarletteHTTPException,
) -> JSONResponse:
    if error.status_code == 404:
        code, message = "not_found", "Resource not found."
    elif error.status_code == 405:
        code, message = "method_not_allowed", "Method not allowed."
    else:
        code, message = "http_error", "The request could not be completed."
    return _response(request, status_code=error.status_code, code=code, message=message)


async def internal_error_handler(request: Request, error: Exception) -> JSONResponse:
    del error
    return _response(
        request,
        status_code=500,
        code="internal_error",
        message="An internal error occurred.",
    )


async def repository_error_handler(
    request: Request,
    error: ReportRepositoryError,
) -> JSONResponse:
    del error
    return _response(
        request,
        status_code=503,
        code="dependency_unavailable",
        message="A required persistence dependency is unavailable.",
    )


def register_error_handlers(app: FastAPI) -> None:
    """Register handlers in one place so every app instance shares the contract."""

    app.add_exception_handler(APIError, api_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ReportRepositoryError, repository_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, internal_error_handler)
