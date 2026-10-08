"""Bounded HTTP client used by the Streamlit demo."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

MAX_QUESTION_CHARACTERS = 2_000
MAX_UPLOAD_BYTES = 5_000_000
MAX_API_RESPONSE_BYTES = 1_000_000


class ApiClientError(RuntimeError):
    """Stable API/client failure safe to render in the demo."""

    def __init__(
        self,
        status_code: int | None,
        code: str,
        message: str,
        correlation_id: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.correlation_id = correlation_id
        super().__init__(f"{code}: {message}")


def validate_api_base_url(value: str) -> str:
    """Accept only a root HTTP(S) origin without credentials or hidden parameters."""

    normalized = value.strip()
    if not normalized or len(normalized) > 2_048 or _contains_control(normalized):
        raise ValueError("API base URL is invalid")
    try:
        parsed = urlsplit(normalized)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("API base URL is invalid") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("API base URL is invalid")
    return normalized.rstrip("/")


def safe_source_url(value: object) -> str | None:
    """Return a link-safe HTTP(S) source URL or None for plain-text rendering."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 2_048
        or _contains_control(value)
    ):
        return None
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return value


class SecRAGraphApiClient:
    """Call only the documented SecRAGraph HTTP endpoints."""

    def __init__(self, base_url: str, *, http_client: httpx.Client) -> None:
        self._base_url = validate_api_base_url(base_url)
        self._http = http_client

    def query_knowledge(self, question: str) -> dict[str, Any]:
        """Send one normalized question to the knowledge endpoint."""

        normalized = _validated_question(question)
        status_code, content = self._send(
            lambda: self._http.stream(
                "POST",
                f"{self._base_url}/v1/knowledge/query",
                json={"question": normalized},
            )
        )
        payload = _decode_response(status_code, content)
        _validate_knowledge_payload(payload, status_code=status_code)
        return payload

    def scan_file(
        self,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> dict[str, Any]:
        """Upload one bounded source file to the scan endpoint."""

        safe_name = _validated_filename(filename)
        if not isinstance(content, bytes) or len(content) > MAX_UPLOAD_BYTES:
            raise ValueError("file content exceeds the client upload limit")
        safe_content_type = _validated_content_type(content_type)
        status_code, response_content = self._send(
            lambda: self._http.stream(
                "POST",
                f"{self._base_url}/v1/scans/file",
                files={"file": (safe_name, content, safe_content_type)},
            )
        )
        return _decode_response(status_code, response_content)

    def _send(
        self,
        request: Callable[[], AbstractContextManager[httpx.Response]],
    ) -> tuple[int, bytes]:
        try:
            with request() as response:
                return response.status_code, _read_bounded_body(response)
        except httpx.TimeoutException as error:
            raise ApiClientError(None, "api_timeout", "The API request timed out.") from error
        except httpx.RequestError as error:
            raise ApiClientError(None, "api_unreachable", "The API is unavailable.") from error


def _validated_question(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("question must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > MAX_QUESTION_CHARACTERS
        or "\x00" in normalized
        or _contains_unsafe_text_control(normalized)
    ):
        raise ValueError("question is invalid")
    return normalized


def _validated_filename(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("filename must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 255
        or Path(normalized).name != normalized
        or "/" in normalized
        or "\\" in normalized
        or ":" in normalized
        or _contains_control(normalized)
    ):
        raise ValueError("filename is invalid")
    return normalized


def _validated_content_type(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("content type must be text")
    normalized = value.split(";", maxsplit=1)[0].strip().lower()
    if not normalized or len(normalized) > 100 or _contains_control(normalized):
        raise ValueError("content type is invalid")
    return normalized


def _read_bounded_body(response: httpx.Response) -> bytes:
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as error:
            raise ApiClientError(
                response.status_code,
                "invalid_api_response",
                "The API response was invalid.",
            ) from error
        if declared_size < 0 or declared_size > MAX_API_RESPONSE_BYTES:
            raise ApiClientError(
                response.status_code,
                "invalid_api_response",
                "The API response was invalid.",
            )

    content = bytearray()
    for chunk in response.iter_bytes():
        if len(content) + len(chunk) > MAX_API_RESPONSE_BYTES:
            raise ApiClientError(
                response.status_code,
                "invalid_api_response",
                "The API response was invalid.",
            )
        content.extend(chunk)
    return bytes(content)


def _decode_response(status_code: int, content: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(content)
    except (UnicodeError, ValueError) as error:
        raise ApiClientError(
            status_code,
            "invalid_api_response",
            "The API response was invalid.",
        ) from error
    if not isinstance(payload, dict):
        raise ApiClientError(
            status_code,
            "invalid_api_response",
            "The API response was invalid.",
        )
    result = dict(payload)
    if 200 <= status_code < 300:
        return result
    code = _safe_error_text(result.get("code"), fallback="api_error", maximum=100)
    message = _safe_error_text(
        result.get("message"),
        fallback="The API request failed.",
        maximum=500,
    )
    correlation_id = _safe_optional_text(result.get("correlation_id"), maximum=100)
    raise ApiClientError(status_code, code, message, correlation_id)


def _validate_knowledge_payload(
    payload: dict[str, Any],
    *,
    status_code: int,
) -> None:
    intent = payload.get("intent")
    answer = payload.get("answer")
    attempts = payload.get("attempts")
    sources = payload.get("sources")
    warnings = payload.get("warnings")
    valid = (
        intent in {"general", "text2sql", "rag"}
        and _valid_text(answer, maximum=20_000, allow_newlines=True)
        and type(attempts) is int
        and 1 <= attempts <= 100
        and isinstance(sources, list)
        and len(sources) <= 20
        and all(_valid_source(source, intent=intent) for source in sources)
        and isinstance(warnings, list)
        and len(warnings) <= 100
        and all(_valid_text(warning, maximum=500) for warning in warnings)
    )
    if not valid:
        raise ApiClientError(
            status_code,
            "invalid_api_response",
            "The API response was invalid.",
        )


def _valid_source(value: object, *, intent: str) -> bool:
    if not isinstance(value, dict):
        return False
    page = value.get("page")
    score = value.get("score")
    source_url = value.get("source_url")
    section = value.get("section")
    return (
        _valid_text(value.get("id"), maximum=1_024)
        and _valid_text(value.get("title"), maximum=300)
        and (source_url is None or _valid_text(source_url, maximum=2_048))
        and (page is None or (type(page) is int and page >= 1))
        and (
            section is None
            or (
                intent == "text2sql"
                and _valid_text(section, maximum=8_192, allow_newlines=True)
                and len(section.encode("utf-8")) <= 8_192
            )
            or (intent != "text2sql" and _valid_text(section, maximum=500))
        )
        and (score is None or _valid_score(score))
    )


def _valid_score(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and 0 <= numeric <= 1


def _valid_text(
    value: object,
    *,
    maximum: int,
    allow_newlines: bool = False,
) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        return False
    if allow_newlines:
        return not _contains_unsafe_text_control(value)
    return not _contains_control(value)


def _safe_error_text(value: object, *, fallback: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _contains_control(value)
    ):
        return fallback
    return value.strip()


def _safe_optional_text(value: object, *, maximum: int) -> str | None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or _contains_control(value)
    ):
        return None
    return value.strip()


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _contains_unsafe_text_control(value: str) -> bool:
    return any(
        (ord(character) < 32 and character not in {"\n", "\r", "\t"}) or ord(character) == 127
        for character in value
    )
