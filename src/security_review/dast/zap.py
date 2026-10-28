"""Bounded OpenAPI and OWASP ZAP Traditional JSON normalization.

Only route templates and a small fixed set of ZAP metadata leave this module.
Request and response material from the untrusted target is never copied into
findings, identifiers, or warnings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import SplitResult, urlsplit

from security_review.domain.models import Confidence, Finding, Severity

MAX_OPENAPI_BYTES = 2_000_000
MAX_ZAP_REPORT_BYTES = 8_000_000
MAX_PATHS = 1_000
MAX_OPERATIONS = 2_000
MAX_SITES = 8
MAX_ALERTS = 2_000
MAX_INSTANCES = 10_000
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_OPENAPI_VERSION = re.compile(r"3\.(?:0|1)\.[0-9]+\Z")
_ROUTE = re.compile(r"/[A-Za-z0-9._~{}/-]{0,1023}\Z")
_PARAMETER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}\Z")
_CWE = re.compile(r"[1-9][0-9]{0,5}\Z")
_PLUGIN = re.compile(r"[1-9][0-9]{0,8}\Z")


class DastInputError(ValueError):
    """The requested DAST target or its OpenAPI description is not safe."""


class DastReportError(ValueError):
    """The external ZAP report is malformed or outside the approved scope."""


@dataclass(frozen=True, slots=True)
class SafeOpenAPI:
    """A target-only, safe-method OpenAPI document for ZAP import."""

    document: bytes
    eligible_endpoints: tuple[str, ...]


def _origin(value: str) -> SplitResult:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "secragraph-target"
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
    except ValueError as error:
        raise DastInputError("invalid_target_origin") from error
    return parsed


def _is_local_ref(value: object) -> bool:
    return isinstance(value, str) and value.startswith("#/") and len(value) <= 512


def _check_refs(payload: object) -> None:
    queue: list[tuple[object, tuple[str, ...]]] = [(payload, ())]
    visited = 0
    while queue:
        current, path = queue.pop()
        visited += 1
        if visited > 40_000:
            raise DastInputError("openapi_too_complex")
        if isinstance(current, dict):
            if "$ref" in current and not _is_local_ref(current["$ref"]):
                raise DastInputError("external_openapi_ref")
            for key, value in current.items():
                if key == "servers" and path:
                    raise DastInputError("nested_openapi_server_override")
                if key == "server" and len(path) >= 2 and path[-2] == "links":
                    raise DastInputError("nested_openapi_server_override")
                queue.append((value, (*path, key)))
        elif isinstance(current, list):
            queue.extend((value, path) for value in current)


def _route_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _ROUTE.fullmatch(value)
        or "//" in value
        or "/./" in value
        or "/../" in value
        or value.endswith("/..")
        or value.endswith("/.")
    ):
        raise DastInputError("invalid_openapi_path")
    for segment in value.strip("/").split("/"):
        if ("{" in segment or "}" in segment) and not _PARAMETER.fullmatch(segment):
            raise DastInputError("invalid_openapi_path")
    return value


def sanitize_openapi(raw: bytes, *, origin: str) -> SafeOpenAPI:
    """Keep only bounded GET/HEAD/OPTIONS paths on the isolated target."""

    _origin(origin)
    if not raw or len(raw) > MAX_OPENAPI_BYTES:
        raise DastInputError("openapi_size_limit")
    try:
        source = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DastInputError("invalid_openapi_json") from error
    if not isinstance(source, dict):
        raise DastInputError("invalid_openapi_document")
    version = source.get("openapi")
    if not isinstance(version, str) or not _OPENAPI_VERSION.fullmatch(version):
        raise DastInputError("unsupported_openapi_version")
    info = source.get("info")
    paths = source.get("paths")
    if not isinstance(info, dict) or not isinstance(paths, dict) or len(paths) > MAX_PATHS:
        raise DastInputError("invalid_openapi_document")
    _check_refs(source)
    safe_paths: dict[str, dict[str, Any]] = {}
    operations: list[str] = []
    for raw_path, raw_item in paths.items():
        path = _route_path(raw_path)
        if not isinstance(raw_item, dict):
            raise DastInputError("invalid_openapi_path_item")
        safe_item: dict[str, Any] = {}
        if "parameters" in raw_item:
            safe_item["parameters"] = raw_item["parameters"]
        for method in sorted(SAFE_METHODS):
            operation = raw_item.get(method.lower())
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise DastInputError("invalid_openapi_operation")
            safe_item[method.lower()] = {
                key: value
                for key, value in operation.items()
                if key not in {"callbacks", "x-codeSamples"}
            }
            operations.append(f"{method} {path}")
            if len(operations) > MAX_OPERATIONS:
                raise DastInputError("openapi_operation_limit")
        if any(key.lower() in {"get", "head", "options"} for key in safe_item):
            safe_paths[path] = safe_item
    if not operations:
        raise DastInputError("no_safe_openapi_operations")
    safe: dict[str, Any] = {
        "openapi": version,
        "info": info,
        "servers": [{"url": origin}],
        "paths": safe_paths,
    }
    for key in ("components", "security", "tags"):
        if key in source:
            safe[key] = source[key]
    document = json.dumps(safe, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(document) > MAX_OPENAPI_BYTES:
        raise DastInputError("openapi_size_limit")
    return SafeOpenAPI(document=document, eligible_endpoints=tuple(sorted(operations)))


def _same_origin(url: object, origin: str) -> str:
    if not isinstance(url, str) or len(url) > 4_096 or any(ord(char) < 32 for char in url):
        raise DastReportError("invalid_zap_url")
    try:
        parsed = urlsplit(url)
        expected = urlsplit(origin)
        if (
            parsed.scheme != expected.scheme
            or parsed.hostname != expected.hostname
            or parsed.port != expected.port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError
    except ValueError as error:
        raise DastReportError("off_scope_zap_result") from error
    return parsed.path or "/"


def _route_matches(route: str, actual: str) -> bool:
    parts = route.strip("/").split("/")
    segments = [r"[^/]{1,256}" if _PARAMETER.fullmatch(part) else re.escape(part) for part in parts]
    pattern = r"/".join(segments)
    return re.fullmatch(r"/" + pattern if route != "/" else r"/", actual) is not None


def _route_for(method: str, actual: str, eligible: tuple[str, ...]) -> str:
    routes = [item.split(" ", 1)[1] for item in eligible if item.startswith(f"{method} ")]
    routes.sort(key=lambda path: (-path.count("/") + path.count("{"), path))
    for route in routes:
        if _route_matches(route, actual):
            return route
    raise DastReportError("unlisted_zap_endpoint")


def _code(value: object, *, maximum: int, error_code: str) -> int:
    if not isinstance(value, str) or len(value) > 2 or not value.isascii() or not value.isdecimal():
        raise DastReportError(error_code)
    number = int(value)
    if not 0 <= number <= maximum:
        raise DastReportError(error_code)
    return number


def parse_zap_report(
    raw: bytes, *, origin: str, eligible_endpoints: tuple[str, ...]
) -> tuple[Finding, ...]:
    """Normalize only scoped ZAP alert metadata, discarding all raw evidence."""

    _origin(origin)
    if not raw or len(raw) > MAX_ZAP_REPORT_BYTES:
        raise DastReportError("zap_report_size_limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DastReportError("invalid_zap_json") from error
    if not isinstance(payload, dict):
        raise DastReportError("invalid_zap_report")
    sites = payload.get("site")
    if not isinstance(sites, list) or not sites or len(sites) > MAX_SITES:
        raise DastReportError("invalid_zap_report")
    findings: dict[tuple[str, str, str], Finding] = {}
    instance_count = 0
    alert_count = 0
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("alerts"), list):
            raise DastReportError("invalid_zap_report")
        _same_origin(site.get("@name", ""), origin)
        alerts = site["alerts"]
        alert_count += len(alerts)
        if alert_count > MAX_ALERTS:
            raise DastReportError("zap_alert_limit")
        for alert in alerts:
            if not isinstance(alert, dict):
                raise DastReportError("invalid_zap_alert")
            raw_plugin = alert.get("pluginid")
            if not isinstance(raw_plugin, str) or not _PLUGIN.fullmatch(raw_plugin):
                raise DastReportError("invalid_zap_rule")
            risk = _code(alert.get("riskcode"), maximum=3, error_code="invalid_zap_risk")
            confidence = _code(
                alert.get("confidence"), maximum=4, error_code="invalid_zap_confidence"
            )
            raw_cwe = alert.get("cweid")
            cwes = (
                (f"CWE-{raw_cwe}",) if isinstance(raw_cwe, str) and _CWE.fullmatch(raw_cwe) else ()
            )
            instances = alert.get("instances")
            if not isinstance(instances, list):
                raise DastReportError("invalid_zap_alert")
            instance_count += len(instances)
            if instance_count > MAX_INSTANCES:
                raise DastReportError("zap_instance_limit")
            for instance in instances:
                if not isinstance(instance, dict):
                    raise DastReportError("invalid_zap_instance")
                method = instance.get("method")
                uri = instance.get("uri")
                if (
                    not isinstance(method, str)
                    or method not in SAFE_METHODS
                    or not isinstance(uri, str)
                ):
                    raise DastReportError("invalid_zap_instance")
                actual = _same_origin(uri, origin)
                route = _route_for(method, actual, eligible_endpoints)
                if confidence == 0:  # ZAP explicitly marked this alert false positive.
                    continue
                rule_id = f"ZAP/{raw_plugin}"
                identity = sha256(f"{rule_id}\0{method}\0{route}".encode()).hexdigest()[:24]
                finding = Finding(
                    id=f"ZAP-{identity}",
                    rule_id=rule_id,
                    category="dast",
                    severity=(Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH)[risk],
                    file_path=None,
                    line_start=None,
                    http_method=method,
                    http_path=route,
                    message=f"ZAP passive rule {raw_plugin} flagged this API operation.",
                    redacted_evidence="[HTTP evidence omitted]",
                    confidence=(
                        Confidence.LOW,
                        Confidence.LOW,
                        Confidence.MEDIUM,
                        Confidence.HIGH,
                        Confidence.HIGH,
                    )[confidence],
                    cwe_ids=cwes,
                    remediation=f"Review OWASP ZAP rule {raw_plugin} and harden the API response.",
                    engine="zap",
                )
                findings[(raw_plugin, method, route)] = finding
    return tuple(findings[key] for key in sorted(findings))
