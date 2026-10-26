"""The local OSV command shares the same version-scoped adapter."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from security_review import cli
from security_review.intelligence.osv import OsvAdvisory, OsvQueryResult


def test_osv_cli_returns_cve_alias_with_source(monkeypatch) -> None:
    class Fake:
        def query_package(self, ecosystem: str, package: str, version: str):
            assert (ecosystem, package, version) == ("PyPI", "jinja2", "2.4.1")
            return OsvQueryResult(
                ecosystem,
                package,
                version,
                (
                    OsvAdvisory(
                        "GHSA-abcd-1234-5678",
                        ("CVE-2024-12345",),
                        "Issue",
                        None,
                        "https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
                    ),
                ),
            )

    monkeypatch.setattr(cli, "_osv_client_factory", lambda: Fake(), raising=False)
    result = CliRunner().invoke(
        cli.app,
        ["osv-query", "--ecosystem", "PyPI", "--package", "jinja2", "--version", "2.4.1"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["advisories"][0]["cve_ids"] == ["CVE-2024-12345"]
