"""Exact lockfile coordinates are the only inputs allowed to reach OSV."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import httpx
import pytest

from security_review.domain.models import Severity
from security_review.intelligence import dependency_osv
from security_review.intelligence.dependency_osv import (
    DependencyAuditResult,
    DependencyCoordinate,
    DependencyQueryError,
    LiveDependencyAuditor,
    LiveDependencyQueryer,
    audit_dependencies,
)
from security_review.intelligence.osv import OsvAdvisory, OsvQueryResult
from security_review.scanner.files import ScanLimits


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class ClockStream(httpx.SyncByteStream):
    def __init__(
        self,
        clock: FakeClock,
        value: float,
        content: bytes,
        *,
        advance_before: bool,
    ) -> None:
        self._clock = clock
        self._value = value
        self._content = content
        self._advance_before = advance_before

    def __iter__(self) -> Iterator[bytes]:
        if self._advance_before:
            self._clock.value = self._value
        yield self._content
        if not self._advance_before:
            self._clock.value = self._value


class RecordingQueryer:
    def __init__(
        self,
        responses: dict[tuple[str, str, str], tuple[OsvAdvisory, ...]] | None = None,
        *,
        error: Exception | None = None,
        omit: frozenset[tuple[str, str, str]] = frozenset(),
    ) -> None:
        self.responses = responses or {}
        self.error = error
        self.omit = omit
        self.calls: list[tuple[DependencyCoordinate, ...]] = []

    def query_batch(
        self, coordinates: Sequence[DependencyCoordinate]
    ) -> dict[DependencyCoordinate, tuple[OsvAdvisory, ...]]:
        self.calls.append(tuple(coordinates))
        if self.error is not None:
            raise self.error
        result: dict[DependencyCoordinate, tuple[OsvAdvisory, ...]] = {}
        for coordinate in coordinates:
            identity = (coordinate.ecosystem, coordinate.name, coordinate.version)
            if identity not in self.omit:
                result[coordinate] = self.responses.get(identity, ())
        return result


def _advisory(identifier: str = "GHSA-test-0001") -> OsvAdvisory:
    return OsvAdvisory(
        id=identifier,
        cve_ids=("CVE-2099-0001",),
        summary="Synthetic advisory summary that must not control severity.",
        published_at="2099-01-01T00:00:00Z",
        source_url=f"https://osv.dev/vulnerability/{identifier}",
    )


def test_uv_lock_queries_only_exact_public_pypi_coordinates(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "Requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "private-project"
version = "1.2.3"
source = { registry = "https://packages.example.com/simple" }

[[package]]
name = "local-project"
version = "0.1.0"
source = { editable = "." }
""".strip(),
        encoding="utf-8",
    )
    queryer = RecordingQueryer({("PyPI", "requests", "2.32.3"): (_advisory(),)})

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert [
        [(item.ecosystem, item.name, item.version) for item in call] for call in queryer.calls
    ] == [[("PyPI", "requests", "2.32.3")]]
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "OSV001"
    assert finding.category == "dependency"
    assert finding.severity is Severity.INFO
    assert finding.file_path == "uv.lock"
    assert finding.cwe_ids == ()
    assert finding.references[0].source_url == "https://osv.dev/vulnerability/GHSA-test-0001"
    assert "CVE-2099-0001" in finding.message
    assert result.warnings == ("dependency_inventory_partial",)


def test_package_lock_v3_queries_transitive_public_npm_and_skips_unsafe_sources(
    tmp_path: Path,
) -> None:
    payload = {
        "name": "root",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            },
            "node_modules/a/node_modules/@scope/pkg": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
            },
            "node_modules/private": {
                "version": "1.0.0",
                "resolved": "https://npm.example.com/private/-/private-1.0.0.tgz",
            },
            "node_modules/link": {"resolved": "../link", "link": True},
            "node_modules/git-dep": {
                "version": "git+https://github.com/example/project.git#deadbeef",
                "resolved": "git+https://github.com/example/project.git#deadbeef",
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(payload), encoding="utf-8")
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert [
        [(item.ecosystem, item.name, item.version) for item in call] for call in queryer.calls
    ] == [[("npm", "@scope/pkg", "2.0.0"), ("npm", "lodash", "4.17.20")]]
    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_npm_alias_and_resolved_package_mismatch_are_not_queried(tmp_path: Path) -> None:
    payload = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/alias": {
                "name": "real-package",
                "version": "1.0.0",
                "resolved": ("https://registry.npmjs.org/real-package/-/real-package-1.0.0.tgz"),
            },
            "node_modules/mismatched-url": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/other/-/other-2.0.0.tgz",
            },
            "node_modules/normal": {
                "version": "3.0.0",
                "resolved": "https://registry.npmjs.org/normal/-/normal-3.0.0.tgz",
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(payload), encoding="utf-8")
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert [
        [(item.ecosystem, item.name, item.version) for item in call] for call in queryer.calls
    ] == [[("npm", "normal", "3.0.0")]]
    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_range_versions_are_never_guessed_as_exact_coordinates(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "demo"\nversion = ">=1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "node_modules/demo": {
                        "version": "^2.0.0",
                        "resolved": "https://registry.npmjs.org/demo/-/demo-2.0.0.tgz",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert queryer.calls == []
    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_registry_tags_are_excluded_while_exact_pep440_and_semver_are_kept(
    tmp_path: Path,
) -> None:
    (tmp_path / "uv.lock").write_text(
        """
version = 1
[[package]]
name = "tagged"
version = "latest"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "exact-python"
version = "1!2.0rc1.post2+cpu.1"
source = { registry = "https://pypi.org/simple" }
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "node_modules/tagged": {
                        "version": "next",
                        "resolved": "https://registry.npmjs.org/tagged/-/tagged-next.tgz",
                    },
                    "node_modules/exact-node": {
                        "version": "2.3.4-rc.1+build.5",
                        "resolved": (
                            "https://registry.npmjs.org/exact-node/-/exact-node-2.3.4.tgz"
                        ),
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert [
        [(item.ecosystem, item.name, item.version) for item in call] for call in queryer.calls
    ] == [
        [
            ("PyPI", "exact-python", "1!2.0rc1.post2+cpu.1"),
            ("npm", "exact-node", "2.3.4-rc.1+build.5"),
        ]
    ]
    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_duplicate_exact_coordinates_are_queried_once_and_reported_at_each_lockfile(
    tmp_path: Path,
) -> None:
    for directory in (tmp_path / "a", tmp_path / "b"):
        directory.mkdir()
        (directory / "uv.lock").write_text(
            'version = 1\n[[package]]\nname = "demo"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n',
            encoding="utf-8",
        )
    queryer = RecordingQueryer({("PyPI", "demo", "1.0"): (_advisory(),)})

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert len(queryer.calls) == 1
    assert len(queryer.calls[0]) == 1
    assert queryer.calls[0][0].lockfile_path == "a/uv.lock"
    assert [finding.file_path for finding in result.findings] == ["a/uv.lock", "b/uv.lock"]
    assert len({finding.id for finding in result.findings}) == 2


def test_missing_batch_result_is_partial_not_a_false_clean_scan(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "one"\nversion = "1"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        '[[package]]\nname = "two"\nversion = "2"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    queryer = RecordingQueryer(
        {("PyPI", "one", "1"): (_advisory(),)},
        omit=frozenset({("PyPI", "two", "2")}),
    )

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert len(result.findings) == 1
    assert result.warnings == ("dependency_osv_partial",)


def test_query_failure_is_a_warning_and_does_not_create_findings(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "demo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    queryer = RecordingQueryer(error=DependencyQueryError("osv_unavailable"))

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert result.findings == ()
    assert result.warnings == ("dependency_osv_unavailable",)


def test_malformed_and_oversized_lockfiles_never_reach_queryer(tmp_path: Path) -> None:
    malformed = tmp_path / "package-lock.json"
    malformed.write_text("{", encoding="utf-8")
    oversized = tmp_path / "nested"
    oversized.mkdir()
    (oversized / "uv.lock").write_bytes(b"x" * 2_000_001)
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert queryer.calls == []
    assert set(result.warnings) == {
        "dependency_lockfile_invalid",
        "dependency_lockfile_too_large",
    }


def test_lockfile_has_a_dedicated_two_megabyte_read_limit(tmp_path: Path) -> None:
    prefix = (
        'version = 1\n[[package]]\nname = "demo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n#'
    )
    (tmp_path / "uv.lock").write_text(
        prefix + ("x" * (1_100_000 - len(prefix))),
        encoding="utf-8",
    )
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert [[(item.name, item.version) for item in call] for call in queryer.calls] == [
        [("demo", "1.0")]
    ]
    assert result == DependencyAuditResult()


def test_symlinked_lockfile_is_not_read_or_queried(tmp_path: Path) -> None:
    outside = tmp_path / "outside.lock"
    outside.write_text(
        'version = 1\n[[package]]\nname = "secret-private-name"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    root = tmp_path / "target"
    root.mkdir()
    try:
        (root / "uv.lock").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    queryer = RecordingQueryer()

    result = audit_dependencies(root, ScanLimits(), queryer)

    assert queryer.calls == []
    assert result.warnings == ("dependency_lockfile_link_skipped",)


def test_walk_error_marks_dependency_inventory_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inaccessible_walk(
        _root: Path,
        *,
        topdown: bool,
        onerror: object = None,
        followlinks: bool,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        del topdown, followlinks
        assert callable(onerror)
        yield str(tmp_path), [], []
        onerror(PermissionError("private path must not leak into warning"))

    monkeypatch.setattr(os, "walk", inaccessible_walk)

    result = audit_dependencies(tmp_path, ScanLimits(), RecordingQueryer())

    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_link_like_directory_is_not_followed_and_marks_inventory_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    linked_directory = tmp_path / "linked"
    linked_directory.mkdir()
    (linked_directory / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "hidden"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    real_is_link_like = dependency_osv._is_link_like

    def fake_is_link_like(path: Path) -> bool:
        return path == linked_directory or real_is_link_like(path)

    monkeypatch.setattr(dependency_osv, "_is_link_like", fake_is_link_like)
    queryer = RecordingQueryer()

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert queryer.calls == []
    assert result == DependencyAuditResult(warnings=("dependency_inventory_partial",))


def test_live_queryer_screens_at_fixed_batch_endpoint_and_expands_only_matches() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url == httpx.URL("https://api.osv.dev/v1/querybatch")
        body = json.loads(request.content)
        assert "uv.lock" not in request.content.decode("utf-8")
        assert body == {
            "queries": [
                {"package": {"ecosystem": "PyPI", "name": "match"}, "version": "1.0"},
                {"package": {"ecosystem": "PyPI", "name": "safe"}, "version": "2.0"},
            ]
        }
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "OSV-2099-1"}]}, {}]},
        )

    class ExactClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str]] = []

        def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
            self.calls.append((ecosystem, package, version))
            return OsvQueryResult(
                ecosystem,
                package,
                version,
                (_advisory("OSV-2099-1"),),
            )

    http_client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    exact = ExactClient()
    queryer = LiveDependencyQueryer(http_client=http_client, osv_client=exact)
    match = DependencyCoordinate("PyPI", "match", "1.0", "uv.lock")
    safe = DependencyCoordinate("PyPI", "safe", "2.0", "uv.lock")

    result = queryer.query_batch((match, safe))

    assert len(requests) == 1
    assert exact.calls == [("PyPI", "match", "1.0")]
    assert result == {match: (_advisory("OSV-2099-1"),), safe: ()}
    http_client.close()


def test_querybatch_page_token_omits_only_truncated_coordinate() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [{"id": "OSV-2099-1"}],
                        "next_page_token": "more-for-first-only",
                    },
                    {},
                ]
            },
        )

    class NeverExactClient:
        def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
            raise AssertionError("truncated screening result must remain partial")

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    queryer = LiveDependencyQueryer(http_client=http_client, osv_client=NeverExactClient())
    truncated = DependencyCoordinate("PyPI", "truncated", "1.0", "uv.lock")
    complete = DependencyCoordinate("PyPI", "complete", "1.0", "uv.lock")

    result = queryer.query_batch((truncated, complete))

    assert result == {complete: ()}
    http_client.close()


def test_live_queryer_shares_one_deadline_across_batch_and_exact_requests() -> None:
    clock = FakeClock()
    exact_timeouts: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url == httpx.URL("https://api.osv.dev/v1/querybatch"):
            payload = json.dumps({"results": [{"vulns": [{"id": "OSV-2099-1"}]}]}).encode("utf-8")
            return httpx.Response(
                200,
                stream=ClockStream(clock, 14.0, payload, advance_before=False),
            )
        assert request.url == httpx.URL("https://api.osv.dev/v1/query")
        exact_timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, json={"vulns": []})

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    queryer = LiveDependencyQueryer(http_client=http_client, clock=clock)
    coordinate = DependencyCoordinate("PyPI", "demo", "1.0", "uv.lock")

    result = queryer.query_batch((coordinate,))

    assert result == {coordinate: ()}
    assert exact_timeouts
    assert all(0 < value <= 1.0 for value in exact_timeouts[0].values())
    http_client.close()


def test_live_queryer_rejects_batch_content_arriving_after_deadline() -> None:
    clock = FakeClock()
    payload = json.dumps({"results": [{}]}).encode("utf-8")
    http_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                stream=ClockStream(clock, 15.0, payload, advance_before=True),
            )
        )
    )
    queryer = LiveDependencyQueryer(http_client=http_client, clock=clock)
    coordinate = DependencyCoordinate("PyPI", "demo", "1.0", "uv.lock")

    with pytest.raises(DependencyQueryError, match="osv_batch_deadline_exceeded"):
        queryer.query_batch((coordinate,))

    http_client.close()


def test_later_batch_failure_preserves_completed_results_as_partial(tmp_path: Path) -> None:
    packages: dict[str, object] = {"": {"name": "root", "version": "1.0.0"}}
    for index in range(101):
        name = f"package-{index:03d}"
        packages[f"node_modules/{name}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
        }
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}),
        encoding="utf-8",
    )
    request_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return httpx.Response(200, json={"results": [{} for _ in range(100)]})
        return httpx.Response(503)

    class NeverExactClient:
        def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
            raise AssertionError("unmatched coordinates must not reach exact lookup")

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    queryer = LiveDependencyQueryer(http_client=http_client, osv_client=NeverExactClient())

    result = audit_dependencies(tmp_path, ScanLimits(), queryer)

    assert request_count == 2
    assert result == DependencyAuditResult(warnings=("dependency_osv_partial",))
    http_client.close()


def test_live_queryer_rejects_redirects_oversize_and_result_count_mismatch() -> None:
    coordinate = DependencyCoordinate("PyPI", "demo", "1", "uv.lock")

    class NeverExactClient:
        def query_package(self, ecosystem: str, package: str, version: str) -> OsvQueryResult:
            raise AssertionError("screening failures must not reach exact OSV lookup")

    exact = NeverExactClient()

    redirect_requests: list[httpx.Request] = []

    def redirect(request: httpx.Request) -> httpx.Response:
        redirect_requests.append(request)
        if request.url == httpx.URL("https://api.osv.dev/v1/querybatch"):
            return httpx.Response(302, headers={"location": "http://127.0.0.1/internal"})
        return httpx.Response(200, json={"results": [{}]})

    redirect_client = httpx.Client(transport=httpx.MockTransport(redirect), follow_redirects=True)
    with pytest.raises(DependencyQueryError, match="osv_batch_failed"):
        LiveDependencyQueryer(
            http_client=redirect_client,
            osv_client=exact,
        ).query_batch((coordinate,))
    assert [request.url for request in redirect_requests] == [
        httpx.URL("https://api.osv.dev/v1/querybatch")
    ]
    redirect_client.close()

    oversized_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"results": [{}], "padding": "x" * 200})
        ),
        follow_redirects=False,
    )
    with pytest.raises(DependencyQueryError, match="osv_batch_response_too_large"):
        LiveDependencyQueryer(
            http_client=oversized_client,
            osv_client=exact,
            max_response_bytes=100,
        ).query_batch((coordinate,))
    oversized_client.close()

    mismatch_client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"results": []})),
        follow_redirects=False,
    )
    with pytest.raises(DependencyQueryError, match="osv_batch_invalid_response"):
        LiveDependencyQueryer(
            http_client=mismatch_client,
            osv_client=exact,
        ).query_batch((coordinate,))
    mismatch_client.close()


def test_live_dependency_auditor_is_the_graph_callable(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8"
    )
    queryer = RecordingQueryer()

    result = LiveDependencyAuditor(queryer)(tmp_path, ScanLimits())

    assert result == DependencyAuditResult()
