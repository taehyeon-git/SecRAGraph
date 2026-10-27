"""Bounded lockfile discovery and exact-coordinate OSV enrichment."""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from math import isfinite
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import TYPE_CHECKING, Literal, Protocol, TypeGuard, cast
from urllib.parse import quote, unquote, urlsplit

import httpx

from security_review.domain.models import Confidence, Finding, Severity, SourceReference
from security_review.scanner.files import ScanLimits

if TYPE_CHECKING:
    from security_review.intelligence.osv import OsvAdvisory, OsvQueryResult

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_LOCKFILES = 32
MAX_LOCKFILE_BYTES = 2_000_000
MAX_LOCKFILE_ENTRIES = 5_000
MAX_COORDINATES = 1_000
MAX_BATCH_SIZE = 100
MAX_BATCH_RESPONSE_BYTES = 1_000_000
MAX_SCREEN_ADVISORIES = 1_000
MAX_ADVISORIES_PER_COORDINATE = 100
MAX_QUERY_SECONDS = 15.0

_LOCKFILE_NAMES = frozenset({"uv.lock", "package-lock.json"})
_PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,212}$")
_NPM_UNSCOPED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,213}$")
_NPM_SCOPED = re.compile(r"^@[A-Za-z0-9][A-Za-z0-9._~-]{0,100}/[A-Za-z0-9][A-Za-z0-9._~-]{0,100}$")
_PYPI_NORMALIZE = re.compile(r"[-_.]+")
_PYPI_EXACT_VERSION = re.compile(
    r"^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$",
    re.IGNORECASE,
)
_NPM_EXACT_VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_MAX_CVE_IDS_PER_FINDING = 10
_UNSUPPORTED_VERSION_PREFIXES = (
    "file:",
    "git:",
    "git+",
    "http:",
    "https:",
    "link:",
    "npm:",
    "workspace:",
)


@dataclass(frozen=True, slots=True)
class DependencyCoordinate:
    """One exact public-registry package coordinate and its first lockfile location."""

    ecosystem: Literal["PyPI", "npm"]
    name: str
    version: str
    lockfile_path: str = field(compare=False)
    line: int = field(default=1, compare=False)

    def __post_init__(self) -> None:
        path = PurePosixPath(self.lockfile_path.replace("\\", "/"))
        if (
            self.ecosystem not in {"PyPI", "npm"}
            or not self.name
            or not self.version
            or not self.lockfile_path
            or path.is_absolute()
            or ".." in path.parts
            or self.line < 1
        ):
            raise ValueError("invalid dependency coordinate")


class DependencyQueryer(Protocol):
    """Resolve exact coordinates without receiving target paths or lockfile bytes."""

    def query_batch(
        self, coordinates: Sequence[DependencyCoordinate]
    ) -> Mapping[DependencyCoordinate, tuple[OsvAdvisory, ...]]: ...


@dataclass(frozen=True, slots=True)
class DependencyAuditResult:
    """Dependency findings and content-free degradation warnings for a scan."""

    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()


class DependencyQueryError(RuntimeError):
    """The advisory service did not provide a bounded, trustworthy response."""


class _ExactOsvClient(Protocol):
    def query_package(
        self,
        ecosystem: str,
        package: str,
        version: str,
    ) -> OsvQueryResult: ...


class LiveDependencyQueryer:
    """Screen exact coordinates in bounded batches, then load matched OSV records."""

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        osv_client: _ExactOsvClient | None = None,
        max_response_bytes: int = MAX_BATCH_RESPONSE_BYTES,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if not 1 <= max_response_bytes <= 4_000_000:
            raise ValueError("max_response_bytes is out of range")
        self._http_client = http_client
        self._osv_client = osv_client
        self._max_response_bytes = max_response_bytes
        self._clock = clock

    def query_batch(
        self, coordinates: Sequence[DependencyCoordinate]
    ) -> Mapping[DependencyCoordinate, tuple[OsvAdvisory, ...]]:
        """Return a value for every completed coordinate; omissions mean partial failure."""

        ordered = tuple(coordinates)
        if len(ordered) > MAX_COORDINATES or len(set(ordered)) != len(ordered):
            raise DependencyQueryError("osv_batch_invalid_request")
        if not ordered:
            return {}
        started = self._clock()
        if not isfinite(started):
            raise DependencyQueryError("osv_batch_deadline_exceeded")
        deadline = started + MAX_QUERY_SECONDS
        if self._http_client is not None:
            exact = self._osv_client or _make_osv_client(
                self._http_client,
                deadline=deadline,
                clock=self._clock,
            )
            return self._query_with_clients(ordered, self._http_client, exact, deadline)
        timeout = httpx.Timeout(5.0, connect=2.0)
        limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
        with httpx.Client(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            exact = self._osv_client or _make_osv_client(
                client,
                deadline=deadline,
                clock=self._clock,
            )
            return self._query_with_clients(ordered, client, exact, deadline)

    def _query_with_clients(
        self,
        coordinates: tuple[DependencyCoordinate, ...],
        client: httpx.Client,
        exact: _ExactOsvClient,
        deadline: float,
    ) -> dict[DependencyCoordinate, tuple[OsvAdvisory, ...]]:
        completed: dict[DependencyCoordinate, tuple[OsvAdvisory, ...]] = {}
        for offset in range(0, len(coordinates), MAX_BATCH_SIZE):
            if _deadline_reached(deadline, self._clock):
                if offset == 0:
                    raise DependencyQueryError("osv_batch_deadline_exceeded")
                break
            batch = coordinates[offset : offset + MAX_BATCH_SIZE]
            try:
                matches = _screen_batch(
                    client,
                    batch,
                    self._max_response_bytes,
                    deadline,
                    self._clock,
                )
            except DependencyQueryError:
                if offset == 0:
                    raise
                break
            for coordinate, matched in zip(batch, matches, strict=True):
                if matched is None:
                    continue
                if not matched:
                    completed[coordinate] = ()
                    continue
                if _deadline_reached(deadline, self._clock):
                    break
                try:
                    result = exact.query_package(
                        coordinate.ecosystem,
                        coordinate.name,
                        coordinate.version,
                    )
                    advisories = result.advisories
                except Exception:  # noqa: S112  # nosec B112
                    # External OSV faults leave this coordinate incomplete.
                    continue
                if _deadline_reached(deadline, self._clock):
                    break
                if (
                    not isinstance(advisories, tuple)
                    or len(advisories) > MAX_ADVISORIES_PER_COORDINATE
                ):
                    continue
                completed[coordinate] = advisories
        return completed


def _make_osv_client(
    client: httpx.Client,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _ExactOsvClient:
    from security_review.intelligence.osv import OsvClient

    return cast(_ExactOsvClient, OsvClient(client, deadline=deadline, clock=clock))


def _deadline_reached(deadline: float, clock: Callable[[], float]) -> bool:
    current = clock()
    return not isfinite(deadline) or not isfinite(current) or current >= deadline


def _require_batch_time(deadline: float, clock: Callable[[], float]) -> None:
    if _deadline_reached(deadline, clock):
        raise DependencyQueryError("osv_batch_deadline_exceeded")


def _batch_timeout(deadline: float, clock: Callable[[], float]) -> httpx.Timeout:
    remaining = deadline - clock()
    if not isfinite(remaining) or remaining <= 0:
        raise DependencyQueryError("osv_batch_deadline_exceeded")
    request_seconds = min(5.0, remaining)
    return httpx.Timeout(request_seconds, connect=min(2.0, request_seconds))


def _screen_batch(
    client: httpx.Client,
    coordinates: tuple[DependencyCoordinate, ...],
    max_response_bytes: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bool | None, ...]:
    payload = {
        "queries": [
            {
                "package": {"ecosystem": item.ecosystem, "name": item.name},
                "version": item.version,
            }
            for item in coordinates
        ]
    }
    timeout = _batch_timeout(deadline, clock)
    try:
        with client.stream(
            "POST",
            OSV_BATCH_URL,
            json=payload,
            headers={"Accept": "application/json"},
            follow_redirects=False,
            timeout=timeout,
        ) as response:
            if response.status_code != 200:
                raise DependencyQueryError("osv_batch_failed")
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > max_response_bytes:
                        raise DependencyQueryError("osv_batch_response_too_large")
                except ValueError as error:
                    raise DependencyQueryError("osv_batch_invalid_response") from error
            raw = bytearray()
            for chunk in response.iter_bytes():
                _require_batch_time(deadline, clock)
                if len(raw) + len(chunk) > max_response_bytes:
                    raise DependencyQueryError("osv_batch_response_too_large")
                raw.extend(chunk)
            _require_batch_time(deadline, clock)
    except DependencyQueryError:
        raise
    except httpx.HTTPError as error:
        raise DependencyQueryError("osv_batch_failed") from error
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise DependencyQueryError("osv_batch_invalid_response") from error
    if not isinstance(document, dict):
        raise DependencyQueryError("osv_batch_invalid_response")
    results = document.get("results")
    if not isinstance(results, list) or len(results) != len(coordinates):
        raise DependencyQueryError("osv_batch_invalid_response")
    matched: list[bool | None] = []
    for result in results:
        if not isinstance(result, dict):
            raise DependencyQueryError("osv_batch_invalid_response")
        page_token = result.get("next_page_token")
        if page_token not in (None, "") and (
            not isinstance(page_token, str) or not 1 <= len(page_token) <= 512
        ):
            raise DependencyQueryError("osv_batch_invalid_response")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > MAX_SCREEN_ADVISORIES:
            raise DependencyQueryError("osv_batch_invalid_response")
        for vulnerability in vulnerabilities:
            if (
                not isinstance(vulnerability, dict)
                or not isinstance(vulnerability.get("id"), str)
                or not 1 <= len(vulnerability["id"]) <= 200
            ):
                raise DependencyQueryError("osv_batch_invalid_response")
        matched.append(None if page_token not in (None, "") else bool(vulnerabilities))
    return tuple(matched)


def audit_dependencies(
    target: Path,
    limits: ScanLimits,
    queryer: DependencyQueryer,
) -> DependencyAuditResult:
    """Discover supported locks, query exact public coordinates, and build INFO findings."""

    candidates, discovery_warnings = _discover_lockfiles(target, limits)
    warnings = list(discovery_warnings)
    coordinates: dict[DependencyCoordinate, DependencyCoordinate] = {}
    occurrences: dict[tuple[str, str, str, str, int], DependencyCoordinate] = {}
    for candidate, relative_path in candidates:
        snapshot, error_code = _read_snapshot(candidate, target, limits)
        if error_code is not None:
            warnings.append(error_code)
            continue
        if snapshot is None:
            warnings.append("dependency_lockfile_unreadable")
            continue
        parsed, partial, invalid = _parse_lockfile(relative_path, snapshot)
        if invalid:
            warnings.append("dependency_lockfile_invalid")
            continue
        if partial:
            warnings.append("dependency_inventory_partial")
        for coordinate in parsed:
            occurrence_key = (
                coordinate.ecosystem,
                coordinate.name,
                coordinate.version,
                coordinate.lockfile_path,
                coordinate.line,
            )
            if occurrence_key in occurrences:
                continue
            if len(occurrences) >= MAX_COORDINATES:
                warnings.append("dependency_inventory_truncated")
                break
            occurrences[occurrence_key] = coordinate
            coordinates.setdefault(coordinate, coordinate)
    ordered_queries = tuple(
        sorted(
            coordinates.values(),
            key=lambda item: (item.ecosystem, item.name, item.version, item.lockfile_path),
        )
    )
    ordered_occurrences = tuple(
        sorted(
            occurrences.values(),
            key=lambda item: (
                item.ecosystem,
                item.name,
                item.version,
                item.lockfile_path,
                item.line,
            ),
        )
    )
    if not ordered_queries:
        return DependencyAuditResult(warnings=_unique_warnings(warnings))
    try:
        queried = queryer.query_batch(ordered_queries)
    except DependencyQueryError:
        warnings.append("dependency_osv_unavailable")
        return DependencyAuditResult(warnings=_unique_warnings(warnings))
    if not isinstance(queried, Mapping):
        warnings.append("dependency_osv_unavailable")
        return DependencyAuditResult(warnings=_unique_warnings(warnings))
    findings: dict[str, Finding] = {}
    for coordinate in ordered_occurrences:
        advisories = queried.get(coordinate)
        if advisories is None or not isinstance(advisories, tuple):
            warnings.append("dependency_osv_partial")
            continue
        if len(advisories) > MAX_ADVISORIES_PER_COORDINATE:
            warnings.append("dependency_osv_partial")
            continue
        for advisory in advisories:
            finding = _advisory_finding(coordinate, advisory)
            if finding is None:
                warnings.append("dependency_osv_partial")
                continue
            findings[finding.id] = finding
    ordered_findings = tuple(
        sorted(
            findings.values(),
            key=lambda item: (item.file_path, item.line_start, item.rule_id, item.id),
        )
    )
    return DependencyAuditResult(
        findings=ordered_findings,
        warnings=_unique_warnings(warnings),
    )


class LiveDependencyAuditor:
    """Graph-compatible callable owning the default bounded OSV query adapter."""

    def __init__(self, queryer: DependencyQueryer | None = None) -> None:
        self._queryer = queryer or LiveDependencyQueryer()

    def __call__(self, target: Path, limits: ScanLimits) -> DependencyAuditResult:
        return audit_dependencies(target, limits, self._queryer)


def _discover_lockfiles(
    target: Path,
    limits: ScanLimits,
) -> tuple[tuple[tuple[Path, str], ...], tuple[str, ...]]:
    if _is_link_like(target):
        warning = ("dependency_lockfile_link_skipped",) if _is_lockfile(target) else ()
        return (), warning
    try:
        resolved_target = target.resolve(strict=True)
    except (OSError, ValueError):
        return (), ("dependency_inventory_unavailable",)
    if resolved_target.is_file():
        if not _is_lockfile(resolved_target):
            return (), ()
        return (((resolved_target, resolved_target.name),), ())
    if not resolved_target.is_dir():
        return (), ("dependency_inventory_unavailable",)
    candidates: list[tuple[Path, str]] = []
    warnings: list[str] = []
    inspected = 0
    stopped = False

    def record_walk_error(_error: OSError) -> None:
        warnings.append("dependency_inventory_partial")

    for current, directory_names, file_names in os.walk(
        resolved_target,
        topdown=True,
        onerror=record_walk_error,
        followlinks=False,
    ):
        current_path = Path(current)
        retained: list[str] = []
        for name in sorted(directory_names):
            inspected += 1
            if inspected > limits.max_candidates:
                warnings.append("dependency_inventory_truncated")
                stopped = True
                break
            child = current_path / name
            if name in limits.excluded_directories:
                continue
            if _is_link_like(child):
                warnings.append("dependency_inventory_partial")
                continue
            retained.append(name)
        directory_names[:] = retained
        if stopped:
            break
        for name in sorted(file_names):
            inspected += 1
            if inspected > limits.max_candidates:
                warnings.append("dependency_inventory_truncated")
                stopped = True
                break
            candidate = current_path / name
            if not _is_lockfile(candidate):
                continue
            if _is_link_like(candidate):
                warnings.append("dependency_lockfile_link_skipped")
                continue
            if len(candidates) >= min(MAX_LOCKFILES, limits.max_files):
                warnings.append("dependency_inventory_truncated")
                stopped = True
                break
            relative_path = candidate.relative_to(resolved_target).as_posix()
            candidates.append((candidate, relative_path))
        if stopped:
            break
    return tuple(sorted(candidates, key=lambda item: item[1])), _unique_warnings(warnings)


def _read_snapshot(
    candidate: Path,
    requested_target: Path,
    limits: ScanLimits,
) -> tuple[bytes | None, str | None]:
    try:
        resolved_target = requested_target.resolve(strict=True)
        root = resolved_target.parent if resolved_target.is_file() else resolved_target
        resolved_candidate = candidate.resolve(strict=True)
        if (
            _is_link_like(candidate)
            or not resolved_candidate.is_relative_to(root)
            or not resolved_candidate.is_file()
        ):
            return None, "dependency_lockfile_link_skipped"
        byte_limit = MAX_LOCKFILE_BYTES
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return None, "dependency_lockfile_link_skipped"
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                snapshot = handle.read(byte_limit + 1)
        finally:
            os.close(descriptor)
        if len(snapshot) > byte_limit:
            return None, "dependency_lockfile_too_large"
        if _is_link_like(candidate) or not candidate.resolve(strict=True).is_relative_to(root):
            return None, "dependency_lockfile_link_skipped"
        return snapshot, None
    except (OSError, ValueError):
        return None, "dependency_lockfile_unreadable"


def _parse_lockfile(
    relative_path: str,
    snapshot: bytes,
) -> tuple[tuple[DependencyCoordinate, ...], bool, bool]:
    try:
        text = snapshot.decode("utf-8")
    except UnicodeDecodeError:
        return (), False, True
    name = PurePosixPath(relative_path).name.lower()
    if name == "uv.lock":
        return _parse_uv_lock(relative_path, text)
    if name == "package-lock.json":
        return _parse_package_lock(relative_path, text)
    return (), False, False


def _parse_uv_lock(
    relative_path: str,
    text: str,
) -> tuple[tuple[DependencyCoordinate, ...], bool, bool]:
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return (), False, True
    packages = document.get("package")
    if document.get("version") != 1 or not isinstance(packages, list):
        return (), False, True
    partial = len(packages) > MAX_LOCKFILE_ENTRIES
    coordinates: list[DependencyCoordinate] = []
    for package in packages[:MAX_LOCKFILE_ENTRIES]:
        if not isinstance(package, dict):
            partial = True
            continue
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        registry = source.get("registry") if isinstance(source, dict) else None
        normalized_name = _pypi_name(name)
        if (
            normalized_name is None
            or not _exact_pypi_version(version)
            or not _public_registry(registry, "pypi.org", "/simple")
        ):
            partial = True
            continue
        coordinates.append(DependencyCoordinate("PyPI", normalized_name, version, relative_path))
    return tuple(coordinates), partial, False


def _parse_package_lock(
    relative_path: str,
    text: str,
) -> tuple[tuple[DependencyCoordinate, ...], bool, bool]:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return (), False, True
    if not isinstance(document, dict) or document.get("lockfileVersion") not in {2, 3}:
        return (), False, True
    packages = document.get("packages")
    if not isinstance(packages, dict):
        return (), False, True
    items = sorted(packages.items(), key=lambda item: str(item[0]))
    partial = len(items) > MAX_LOCKFILE_ENTRIES
    coordinates: list[DependencyCoordinate] = []
    for package_path, package in items[:MAX_LOCKFILE_ENTRIES]:
        if package_path == "":
            continue
        if not isinstance(package_path, str) or not isinstance(package, dict):
            partial = True
            continue
        name = _npm_name_from_path(package_path)
        declared_name = package.get("name")
        version = package.get("version")
        resolved = package.get("resolved")
        if (
            name is None
            or (declared_name is not None and declared_name != name)
            or package.get("link") is True
            or not _exact_npm_version(version)
            or version.lower().startswith(_UNSUPPORTED_VERSION_PREFIXES)
            or not _public_npm_tarball(resolved, name)
        ):
            partial = True
            continue
        coordinates.append(DependencyCoordinate("npm", name, version, relative_path))
    return tuple(coordinates), partial, False


def _pypi_name(value: object) -> str | None:
    if not isinstance(value, str) or not _PYPI_NAME.fullmatch(value):
        return None
    return _PYPI_NORMALIZE.sub("-", value).lower()


def _npm_name_from_path(value: str) -> str | None:
    marker = "node_modules/"
    if marker not in value:
        return None
    name = value.rsplit(marker, maxsplit=1)[-1]
    if _NPM_UNSCOPED.fullmatch(name) or _NPM_SCOPED.fullmatch(name):
        return name
    return None


def _exact_pypi_version(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _PYPI_EXACT_VERSION.fullmatch(value) is not None


def _exact_npm_version(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _NPM_EXACT_VERSION.fullmatch(value) is not None


def _public_registry(
    value: object,
    hostname: str,
    required_path: str | None,
) -> bool:
    if not isinstance(value, str) or len(value) > 2_048:
        return False
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
        ):
            return False
    except ValueError:
        return False
    if required_path is not None and parsed.path.rstrip("/") != required_path:
        return False
    return True


def _public_npm_tarball(value: object, package_name: str) -> bool:
    if not isinstance(value, str) or not _public_registry(value, "registry.npmjs.org", None):
        return False
    try:
        decoded_path = unquote(urlsplit(value).path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return False
    package_path, separator, filename = decoded_path.partition("/-/")
    return (
        bool(separator)
        and package_path == f"/{package_name}"
        and bool(filename)
        and "/" not in filename
        and filename.endswith(".tgz")
    )


def _advisory_finding(
    coordinate: DependencyCoordinate,
    advisory: object,
) -> Finding | None:
    identifier = getattr(advisory, "id", None)
    source_url = getattr(advisory, "source_url", None)
    if (
        not isinstance(identifier, str)
        or not 1 <= len(identifier) <= 200
        or not isinstance(source_url, str)
        or not _safe_osv_source(source_url, identifier)
    ):
        return None
    cve_ids = _validated_cve_ids(advisory)
    cve_text = f" (CVE aliases: {', '.join(cve_ids)})" if cve_ids else ""
    digest = sha256(
        "\x00".join(
            (
                coordinate.ecosystem,
                coordinate.name,
                coordinate.version,
                coordinate.lockfile_path,
                str(coordinate.line),
                identifier,
            )
        ).encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()[:20]
    return Finding(
        id=f"OSV001:{digest}",
        rule_id="OSV001",
        category="dependency",
        severity=Severity.INFO,
        file_path=coordinate.lockfile_path,
        line_start=coordinate.line,
        message=(
            f"OSV advisory {identifier}{cve_text} matches exact locked dependency "
            f"{coordinate.name} {coordinate.version}."
        ),
        redacted_evidence="Exact locked dependency coordinate matched an OSV advisory.",
        confidence=Confidence.HIGH,
        cwe_ids=(),
        remediation="Review the linked OSV advisory and upgrade to a confirmed fixed version.",
        references=(
            SourceReference(
                id=f"osv:{identifier}",
                title=identifier,
                source_url=source_url,
            ),
        ),
    )


def _validated_cve_ids(advisory: object) -> tuple[str, ...]:
    raw = getattr(advisory, "cve_ids", ())
    if not isinstance(raw, tuple):
        return ()
    valid = {
        item
        for item in raw
        if isinstance(item, str) and len(item) <= 32 and _CVE_ID.fullmatch(item) is not None
    }
    return tuple(sorted(valid))[:_MAX_CVE_IDS_PER_FINDING]


def _safe_osv_source(source_url: str, identifier: str) -> bool:
    expected = f"/vulnerability/{quote(identifier, safe=':_.-')}"
    try:
        parsed = urlsplit(source_url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "osv.dev"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and parsed.path == expected
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def _is_lockfile(path: Path) -> bool:
    return path.name.lower() in _LOCKFILE_NAMES


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _unique_warnings(warnings: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(warnings))
