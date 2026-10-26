"""Bounded HTTP client used by the Streamlit demo."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

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

    def __init__(
        self,
        base_url: str,
        *,
        http_client: httpx.Client,
        token: str | None = None,
        session_token: str | None = None,
    ) -> None:
        self._base_url = validate_api_base_url(base_url)
        self._http = http_client
        if token is not None and session_token is not None:
            raise ValueError("Choose only one credential mode")
        if token is not None and (
            not token.strip() or token != token.strip() or _contains_control(token)
        ):
            raise ValueError("API token is invalid")
        if session_token is not None and (
            not session_token.strip()
            or session_token != session_token.strip()
            or len(session_token) > 256
            or _contains_control(session_token)
        ):
            raise ValueError("session token is invalid")
        self._headers = (
            {"Authorization": f"Bearer {token}"}
            if token is not None
            else {"Authorization": f"Session {session_token}"}
            if session_token is not None
            else {}
        )

    def register(self, username: str, password: str) -> dict[str, Any]:
        """Request optional development self-registration."""

        credentials = _validated_credentials(username, password)
        status, content, _ = self._send(
            lambda: self._http.stream(
                "POST", f"{self._base_url}/v1/auth/register", json=credentials, headers={}
            )
        )
        payload = _decode_response(status, content)
        _validate_member_payload(payload, status_code=status)
        return payload

    def login(self, username: str, password: str) -> dict[str, Any]:
        """Exchange a member password for an opaque session without an operator key."""

        credentials = _validated_credentials(username, password)
        status, content, _ = self._send(
            lambda: self._http.stream(
                "POST", f"{self._base_url}/v1/auth/login", json=credentials, headers={}
            )
        )
        payload = _decode_response(status, content)
        token = payload.get("token")
        expiry = payload.get("expires_at")
        username_value = payload.get("username")
        if (
            not isinstance(token, str)
            or not _valid_text(token, maximum=256)
            or token != token.strip()
            or not _valid_text(expiry, maximum=64)
            or not _valid_text(username_value, maximum=32)
        ):
            raise ApiClientError(status, "invalid_api_response", "The API response was invalid.")
        return payload

    def me(self) -> dict[str, Any]:
        """Read the current member identity."""

        status, content, _ = self._send(
            lambda: self._http.stream("GET", f"{self._base_url}/v1/auth/me", headers=self._headers)
        )
        payload = _decode_response(status, content)
        _validate_member_payload(payload, status_code=status)
        return payload

    def logout(self) -> None:
        """Revoke the current member session."""

        status, content, _ = self._send(
            lambda: self._http.stream(
                "POST", f"{self._base_url}/v1/auth/logout", headers=self._headers
            )
        )
        if status == 204 and not content:
            return
        if not 200 <= status < 300:
            _decode_response(status, content)
        raise ApiClientError(status, "invalid_api_response", "The API response was invalid.")

    def query_knowledge(self, question: str) -> dict[str, Any]:
        """Send one normalized question to the knowledge endpoint."""

        normalized = _validated_question(question)
        status_code, content, _content_type = self._send(
            lambda: self._http.stream(
                "POST",
                f"{self._base_url}/v1/knowledge/query",
                json={"question": normalized},
                headers=self._headers,
            )
        )
        payload = _decode_response(status_code, content)
        _validate_knowledge_payload(payload, status_code=status_code)
        return payload

    def query_vulnerabilities(self, ecosystem: str, package: str, version: str) -> dict[str, Any]:
        """Query OSV evidence for an explicitly named package version."""

        values = (ecosystem, package, version)
        limits = (40, 255, 100)
        if any(
            not isinstance(value, str)
            or not _valid_text(value, maximum=limit)
            or value != value.strip()
            for value, limit in zip(values, limits, strict=True)
        ):
            raise ValueError("package query is invalid")
        status, content, _ = self._send(
            lambda: self._http.stream(
                "POST",
                f"{self._base_url}/v1/vulnerabilities/query",
                json={"ecosystem": ecosystem, "package": package, "version": version},
                headers=self._headers,
            )
        )
        payload = _decode_response(status, content)
        advisories = payload.get("advisories")
        valid = (
            all(
                payload.get(key) == value
                for key, value in zip(("ecosystem", "package", "version"), values, strict=True)
            )
            and isinstance(advisories, list)
            and len(advisories) <= 500
            and all(_valid_osv_advisory(item) for item in advisories)
        )
        if not valid:
            raise ApiClientError(status, "invalid_api_response", "The API response was invalid.")
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
        status_code, response_content, _content_type = self._send(
            lambda: self._http.stream(
                "POST",
                f"{self._base_url}/v1/scans/file",
                files={"file": (safe_name, content, safe_content_type)},
                headers=self._headers,
            )
        )
        return _decode_response(status_code, response_content)

    def get_report_format(self, scan_id: str, report_format: Literal["markdown", "sarif"]) -> bytes:
        """Fetch one persisted report as bounded Markdown or SARIF bytes."""

        try:
            normalized_id = str(UUID(scan_id))
        except (TypeError, ValueError) as error:
            raise ValueError("scan ID is invalid") from error
        if report_format not in {"markdown", "sarif"}:
            raise ValueError("report format is invalid")
        status_code, content, content_type = self._send(
            lambda: self._http.stream(
                "GET",
                f"{self._base_url}/v1/scans/{normalized_id}/report?format={report_format}",
                headers=self._headers,
            )
        )
        if not 200 <= status_code < 300:
            _decode_response(status_code, content)
        expected_type = "text/markdown" if report_format == "markdown" else "application/sarif+json"
        if not content_type.lower().startswith(expected_type):
            raise ApiClientError(
                status_code, "invalid_api_response", "The API response was invalid."
            )
        return content

    def _send(
        self,
        request: Callable[[], AbstractContextManager[httpx.Response]],
    ) -> tuple[int, bytes, str]:
        try:
            with request() as response:
                return (
                    response.status_code,
                    _read_bounded_body(response),
                    response.headers.get("content-type", ""),
                )
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


def _validated_credentials(username: str, password: str) -> dict[str, str]:
    if (
        not isinstance(username, str)
        or not 1 <= len(username) <= 32
        or _contains_control(username)
        or not isinstance(password, str)
        or not password
        or len(password.encode("utf-8")) > 1_024
        or _contains_control(password)
    ):
        raise ValueError("credentials are invalid")
    return {"username": username, "password": password}


def _validate_member_payload(payload: dict[str, Any], *, status_code: int) -> None:
    username = payload.get("username")
    user_id = payload.get("user_id")
    try:
        valid_id = str(UUID(user_id)) == user_id
    except (TypeError, ValueError, AttributeError):
        valid_id = False
    if not valid_id or not _valid_text(username, maximum=32):
        raise ApiClientError(status_code, "invalid_api_response", "The API response was invalid.")


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


def _valid_osv_advisory(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    ids = value.get("cve_ids")
    source_url = value.get("source_url")
    published = value.get("published_at")
    return (
        _valid_text(value.get("id"), maximum=128)
        and isinstance(ids, list)
        and len(ids) <= 100
        and all(
            _valid_text(identifier, maximum=32) and identifier.startswith("CVE-")
            for identifier in ids
        )
        and _valid_text(value.get("summary"), maximum=500)
        and isinstance(source_url, str)
        and source_url.startswith("https://osv.dev/vulnerability/")
        and safe_source_url(source_url) is not None
        and (published is None or _valid_text(published, maximum=64))
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
