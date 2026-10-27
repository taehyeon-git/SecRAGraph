"""Bounded OSV.dev lookup for an explicitly named package and version."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from time import monotonic
from typing import Any

import httpx

_ORIGIN = "https://api.osv.dev"
_ECOSYSTEM = re.compile(r"[A-Za-z][A-Za-z0-9.+_-]{0,39}\Z")
_PACKAGE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._+@/-]{0,254}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!~:-]{0,99}\Z")
_OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_PAGES = 8
_MAX_RECORDS = 500


class OsvInputError(ValueError):
    """The package identity is not suitable for a bounded lookup."""


class OsvUnavailableError(RuntimeError):
    """OSV could not produce a complete, valid response."""

    def __init__(self) -> None:
        super().__init__("OSV vulnerability data is unavailable")


@dataclass(frozen=True)
class OsvAdvisory:
    id: str
    cve_ids: tuple[str, ...]
    summary: str
    published_at: str | None
    source_url: str


@dataclass(frozen=True)
class OsvQueryResult:
    ecosystem: str
    package: str
    version: str
    advisories: tuple[OsvAdvisory, ...]


def _validated(value: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or ".." in value:
        raise OsvInputError("invalid package query")
    return value


def _same_package(ecosystem: object, name: object, wanted_ecosystem: str, wanted_name: str) -> bool:
    if ecosystem != wanted_ecosystem or not isinstance(name, str):
        return False
    if ecosystem == "PyPI":

        def normalize(item: str) -> str:
            return re.sub(r"[-_.]+", "-", item).lower()

        return normalize(name) == normalize(wanted_name)
    return name == wanted_name


def _parse_advisory(item: object, *, ecosystem: str, package: str) -> OsvAdvisory | None:
    if not isinstance(item, dict):
        raise OsvUnavailableError()
    identifier = item.get("id")
    if not isinstance(identifier, str) or _OSV_ID.fullmatch(identifier) is None:
        raise OsvUnavailableError()
    if item.get("withdrawn") is not None:
        return None
    affected = item.get("affected")
    if not isinstance(affected, list) or len(affected) > 1_000:
        raise OsvUnavailableError()
    if not any(
        isinstance(entry, dict)
        and isinstance(entry.get("package"), dict)
        and _same_package(
            entry["package"].get("ecosystem"),
            entry["package"].get("name"),
            ecosystem,
            package,
        )
        for entry in affected
    ):
        return None
    aliases = item.get("aliases", [])
    if not isinstance(aliases, list) or len(aliases) > 100:
        raise OsvUnavailableError()
    if not all(isinstance(alias, str) for alias in aliases):
        raise OsvUnavailableError()
    cve_ids = tuple(sorted({alias for alias in [identifier, *aliases] if _CVE_ID.fullmatch(alias)}))
    summary = item.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = "No summary provided by OSV."
    summary = summary.strip()[:500]
    if any(ord(character) < 32 or ord(character) == 127 for character in summary):
        raise OsvUnavailableError()
    published = item.get("published")
    if published is not None:
        if not isinstance(published, str) or len(published) > 64:
            raise OsvUnavailableError()
        try:
            parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError as error:
            raise OsvUnavailableError() from error
        if parsed.tzinfo is None:
            raise OsvUnavailableError()
    return OsvAdvisory(
        id=identifier,
        cve_ids=cve_ids,
        summary=summary,
        published_at=published,
        source_url=f"https://osv.dev/vulnerability/{identifier}",
    )


class OsvClient:
    """Query OSV over a fixed HTTPS origin without following redirects."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        deadline: float | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if deadline is not None and not isfinite(deadline):
            raise ValueError("deadline must be finite")
        self._client = client
        self._deadline = deadline
        self._clock = clock

    def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
        ecosystem = _validated(ecosystem, _ECOSYSTEM)
        package = _validated(package, _PACKAGE)
        version = _validated(version, _VERSION)
        base: dict[str, Any] = {
            "package": {"ecosystem": ecosystem, "name": package},
            "version": version,
        }
        seen_tokens: set[str] = set()
        advisories: dict[str, OsvAdvisory] = {}
        raw_count = 0
        page_token: str | None = None
        for _ in range(_MAX_PAGES):
            payload = dict(base)
            if page_token is not None:
                payload["page_token"] = page_token
            result = self._request(payload)
            raw = result.get("vulns", [])
            if not isinstance(raw, list):
                raise OsvUnavailableError()
            raw_count += len(raw)
            if raw_count > _MAX_RECORDS:
                raise OsvUnavailableError()
            for item in raw:
                advisory = _parse_advisory(item, ecosystem=ecosystem, package=package)
                if advisory is not None:
                    advisories.setdefault(advisory.id, advisory)
            next_token = result.get("next_page_token")
            if next_token is None:
                return OsvQueryResult(ecosystem, package, version, tuple(advisories.values()))
            if (
                not isinstance(next_token, str)
                or not 1 <= len(next_token) <= 512
                or next_token in seen_tokens
            ):
                raise OsvUnavailableError()
            seen_tokens.add(next_token)
            page_token = next_token
        raise OsvUnavailableError()

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        timeout = self._request_timeout()
        try:
            with self._client.stream(
                "POST",
                f"{_ORIGIN}/v1/query",
                json=payload,
                follow_redirects=False,
                timeout=timeout,
            ) as response:
                if response.status_code != 200:
                    raise OsvUnavailableError()
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        size = int(declared)
                    except ValueError as error:
                        raise OsvUnavailableError() from error
                    if size < 0 or size > _MAX_RESPONSE_BYTES:
                        raise OsvUnavailableError()
                content = bytearray()
                for chunk in response.iter_bytes():
                    self._require_time_remaining()
                    if len(content) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise OsvUnavailableError()
                    content.extend(chunk)
                self._require_time_remaining()
        except httpx.RequestError as error:
            raise OsvUnavailableError() from error
        try:
            parsed = json.loads(content)
        except (UnicodeError, ValueError) as error:
            raise OsvUnavailableError() from error
        if not isinstance(parsed, dict):
            raise OsvUnavailableError()
        return parsed

    def _request_timeout(self) -> httpx.Timeout:
        if self._deadline is None:
            return httpx.Timeout(10.0, connect=3.0)
        remaining = self._deadline - self._clock()
        if not isfinite(remaining) or remaining <= 0:
            raise OsvUnavailableError()
        request_seconds = min(10.0, remaining)
        return httpx.Timeout(request_seconds, connect=min(3.0, request_seconds))

    def _require_time_remaining(self) -> None:
        if self._deadline is None:
            return
        current = self._clock()
        if not isfinite(current) or current >= self._deadline:
            raise OsvUnavailableError()


class LiveOsvClient:
    """Own one short-lived HTTP connection per explicit package lookup."""

    def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
        with httpx.Client(follow_redirects=False) as client:
            return OsvClient(client).query_package(ecosystem, package, version)
