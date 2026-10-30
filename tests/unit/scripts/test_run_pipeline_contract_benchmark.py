"""The controlled-provider benchmark exercises the real scan graph without a network."""

from __future__ import annotations

import json
import re
from pathlib import Path

from scripts import run_pipeline_contract_benchmark as benchmark
from security_review.intelligence.dependency_osv import DependencyQueryError


def test_contract_benchmark_covers_graph_ports_and_persists_safe_evidence(tmp_path: Path) -> None:
    assert benchmark.main(["--output-dir", str(tmp_path)]) == 0

    raw = (tmp_path / "pipeline-contract.json").read_text(encoding="utf-8")
    result = json.loads(raw)
    markdown = (tmp_path / "pipeline-contract.md").read_text(encoding="utf-8")

    assert result["schema_version"] == 1
    assert result["scope"] == "synthetic_adapter_contract"
    assert result["passed"] is True
    assert re.fullmatch(r"[0-9a-f]{40}", result["source_revision"])
    assert result["coverage"] == {"cases_passed": 1, "cases_total": 1}
    assert result["providers"]["dependency_audit"]["calls"] == 1
    assert result["providers"]["cwe"]["calls"] == 1
    assert result["providers"]["rag"]["calls"] == 2
    assert result["providers"]["rag"]["osv_finding_cited"] is True
    assert result["providers"]["dependency_audit"]["coordinates"] == [
        "PyPI:pipeline-fixture-pkg:1.0.0"
    ]
    assert result["providers"]["cwe"]["requested_ids"] == ["CWE-95"]
    assert result["report"]["status"] == "completed"
    assert result["report"]["finding_count"] == 2
    assert result["report"]["persisted"] is True
    assert result["report"]["reference_ids_by_engine"]["fixture_sast"] == [
        "mitre:CWE-95",
        "fixture:guide:1",
    ]
    assert result["report"]["reference_ids_by_engine"]["osv"] == [
        "osv:OSV-TEST-0001",
        "fixture:guide:1",
    ]
    assert result["report"]["executions"]["osv"]["status"] == "completed"
    assert result["report"]["executions"]["osv"]["scanned_files"] == ["uv.lock"]
    assert result["retrieval_calls"] == {
        "identical_findings": 20,
        "observed_calls": 1,
        "all_cited": True,
    }
    assert result["elapsed_ms"] >= 0
    assert "not live" in markdown.lower()
    assert "eval(input())" not in raw + markdown
    assert "pipeline-fixture-pkg" not in markdown


def test_contract_benchmark_fails_closed_on_provider_failure(tmp_path: Path, monkeypatch) -> None:
    def unavailable(_self, _coordinates):
        raise DependencyQueryError("private failure detail")

    monkeypatch.setattr(benchmark._FixtureQueryer, "query_batch", unavailable)

    assert benchmark.main(["--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / "pipeline-contract.json").exists()
    assert not (tmp_path / "pipeline-contract.md").exists()
