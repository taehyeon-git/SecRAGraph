import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import security_review.application as application_module
import security_review.cli as cli_module
from security_review.application import scan_path
from security_review.cli import app
from security_review.domain.models import Confidence, Finding, Severity, SourceReference
from security_review.intelligence.dependency_osv import DependencyCoordinate, LiveDependencyAuditor
from security_review.intelligence.ingestion import DocumentIngestionError
from security_review.intelligence.osv import OsvAdvisory
from security_review.orchestrator.scan_graph import DeterministicScanResult, ScanRequest
from security_review.reporting.builder import build_report
from security_review.scanner.external_common import ExternalExecution, ExternalScanResult
from security_review.scanner.files import ScanLimits
from security_review.storage.intelligence import ImportSummary

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_live_cwe_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI tests exercise injection, not the live MITRE network."""

    monkeypatch.setattr(
        cli_module,
        "_cwe_evidence_factory",
        lambda: SimpleNamespace(
            ensure=lambda _ids, **_kwargs: SimpleNamespace(references_by_id={}, warnings=())
        ),
        raising=False,
    )


def test_cli_scan_automatically_prepares_cwe_for_real_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    seen: list[tuple[str, ...]] = []
    reference = SourceReference(
        id="mitre:CWE-95",
        title="CWE-95",
        source_url="https://cwe-api.mitre.org/api/v1/cwe/weakness/95",
    )

    def ensure(ids: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        seen.append(ids)
        return SimpleNamespace(references_by_id={"CWE-95": reference}, warnings=())

    def deterministic_scan(request: ScanRequest) -> DeterministicScanResult:
        return DeterministicScanResult(
            target_name=request.target_name or request.target.name,
            findings=(
                Finding(
                    id="opengrep:synthetic-flow",
                    rule_id="OPENGREP/CWE-95",
                    category="code_pattern",
                    severity=Severity.HIGH,
                    file_path="app.py",
                    line_start=1,
                    message="Untrusted input reaches dynamic evaluation.",
                    redacted_evidence="[REDACTED: source omitted]",
                    confidence=Confidence.HIGH,
                    cwe_ids=("CWE-95",),
                    remediation="Use a restricted parser.",
                    engine="opengrep",
                ),
            ),
            warnings=(),
        )

    monkeypatch.setattr(application_module, "_deterministic_scan", deterministic_scan)
    monkeypatch.setattr(
        cli_module,
        "_cwe_evidence_factory",
        lambda: SimpleNamespace(ensure=ensure),
    )
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert seen == [("CWE-95",)]
    assert any(
        item["source_url"] == reference.source_url
        for item in json.loads(result.stdout)["findings"][0]["references"]
    )


def test_cli_offline_scan_does_not_prepare_cwe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_cwe_evidence_factory",
        lambda: pytest.fail("offline scan must not create a CWE provider"),
    )

    result = runner.invoke(app, ["scan", str(target), "--format", "json", "--offline"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["total"] >= 0
    assert {item["engine"] for item in report["executions"]} >= {
        "opengrep",
        "gitleaks",
        "checkov",
    }


def test_cli_writes_json_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["scan", "examples/insecure", "--format", "json", "--output", str(output)],
    )

    assert result.exit_code == 0, result.stdout
    rendered = output.read_text(encoding="utf-8")
    payload = json.loads(rendered)
    assert {item["engine"] for item in payload["executions"]} >= {
        "opengrep",
        "gitleaks",
        "checkov",
    }
    assert "demo-not-a-real-secret-12345" not in rendered


def test_cli_creates_parent_directory_for_sarif_output(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "sample.sarif"

    result = runner.invoke(
        app,
        ["scan", "examples/insecure", "--format", "sarif", "--output", str(output)],
    )

    assert result.exit_code == 0, result.stdout
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_sarif_locations_are_relative_to_invocation_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("eval('unsafe')", encoding="utf-8")
    output = tmp_path / "scan.sarif"
    sample = Finding(
        id="opengrep:sample",
        rule_id="OPENGREP/SAMPLE",
        category="code_pattern",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=1,
        message="Synthetic source-flow finding.",
        redacted_evidence="[REDACTED: source omitted]",
        confidence=Confidence.HIGH,
        remediation="Validate untrusted input.",
        engine="opengrep",
    )
    monkeypatch.setattr(
        cli_module, "scan_path", lambda *_args, **_kwargs: build_report("src", [sample])
    )
    original_cwd = Path.cwd()
    try:
        import os

        os.chdir(tmp_path)
        result = runner.invoke(app, ["scan", "src", "--format", "sarif", "--output", str(output)])
    finally:
        os.chdir(original_cwd)

    assert result.exit_code == 0, result.stdout
    sarif = json.loads(output.read_text(encoding="utf-8"))
    finding = sarif["runs"][0]["results"][0]
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ("src/app.py")
    assert finding["partialFingerprints"]["primaryLocationLineHash"]


def test_cli_rejects_existing_unsupported_single_file(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("nothing to scan", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--format", "json"])

    assert result.exit_code == 2
    assert "unsupported_extension" in result.output


def test_cli_succeeds_with_no_findings(tmp_path: Path) -> None:
    target = tmp_path / "safe.py"
    target.write_text("answer = 42", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--format", "json"])

    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["summary"]["total"] == 0


def test_cli_scan_automatically_runs_dependency_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "safe.py"
    target.write_text("answer = 42", encoding="utf-8")
    calls: list[Path] = []

    def fake_auditor(path: Path, _limits: ScanLimits) -> SimpleNamespace:
        calls.append(path)
        return SimpleNamespace(findings=(), warnings=())

    monkeypatch.setattr(cli_module, "_dependency_auditor_factory", lambda: fake_auditor)

    result = runner.invoke(app, ["scan", str(target), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert calls == [target.resolve()]


def test_cli_scan_offline_makes_no_dependency_auditor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "safe.py"
    target.write_text("answer = 42", encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_dependency_auditor_factory",
        lambda: pytest.fail("offline scan must not create an OSV auditor"),
        raising=False,
    )

    result = runner.invoke(app, ["scan", str(target), "--format", "json", "--offline"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["summary"]["total"] == 0


def test_cli_scan_auto_osv_adds_returned_cve_to_canonical_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("answer = 42\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/vulnerable": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/vulnerable/-/vulnerable-1.0.0.tgz",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    requested: list[DependencyCoordinate] = []

    class FakeQueryer:
        def query_batch(
            self, coordinates: tuple[DependencyCoordinate, ...]
        ) -> dict[DependencyCoordinate, tuple[OsvAdvisory, ...]]:
            requested.extend(coordinates)
            return {
                coordinates[0]: (
                    OsvAdvisory(
                        id="GHSA-abcd-1234-5678",
                        cve_ids=("CVE-2020-1234",),
                        summary="Affected exact package version.",
                        published_at=None,
                        source_url="https://osv.dev/vulnerability/GHSA-abcd-1234-5678",
                    ),
                )
            }

    monkeypatch.setattr(
        cli_module,
        "_dependency_auditor_factory",
        lambda: LiveDependencyAuditor(FakeQueryer()),
    )

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert [(item.ecosystem, item.name, item.version) for item in requested] == [
        ("npm", "vulnerable", "1.0.0")
    ]
    report = json.loads(result.stdout)
    assert report["summary"]["total"] == 1
    finding = report["findings"][0]
    assert finding["rule_id"] == "OSV001"
    assert "CVE-2020-1234" in finding["message"]
    assert finding["references"][0]["source_url"] == (
        "https://osv.dev/vulnerability/GHSA-abcd-1234-5678"
    )


@pytest.mark.parametrize("lockfile_name", ["uv.lock", "package-lock.json"])
def test_cli_accepts_single_lockfile_for_dependency_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lockfile_name: str
) -> None:
    target = tmp_path / lockfile_name
    target.write_text("invalid lock data", encoding="utf-8")
    calls: list[Path] = []

    def fake_auditor(path: Path, _limits: ScanLimits) -> SimpleNamespace:
        calls.append(path)
        return SimpleNamespace(findings=(), warnings=("dependency_lockfile_invalid",))

    monkeypatch.setattr(cli_module, "_dependency_auditor_factory", lambda: fake_auditor)
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert calls == [target.resolve()]
    warnings = json.loads(result.stdout)["warnings"]
    assert "dependency_lockfile_invalid" in warnings
    assert f"{lockfile_name}:unsupported_extension" not in warnings


def test_offline_uv_lock_scan_reports_unchecked_dependency_scope(tmp_path: Path) -> None:
    target = tmp_path / "uv.lock"
    target.write_text("version = 1\npackage = []\n", encoding="utf-8")

    direct = runner.invoke(app, ["scan", str(target), "--format", "json", "--offline"])
    directory = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--offline"])

    assert direct.exit_code == directory.exit_code == 0
    for result in (direct, directory):
        report = json.loads(result.stdout)
        assert report["status"] == "completed_with_warnings"
        assert "uv.lock:unsupported_extension" in report["warnings"]


def test_scan_stops_with_stable_warning_after_deadline(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    (tmp_path / "a.py").write_text("value = first\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("value = second\n", encoding="utf-8")
    now = [0.0]
    sample = Finding(
        id="opengrep:deadline-sample",
        rule_id="OPENGREP/SAMPLE",
        category="code_pattern",
        severity=Severity.HIGH,
        file_path="a.py",
        line_start=1,
        message="Synthetic source-flow finding.",
        redacted_evidence="[REDACTED: source omitted]",
        confidence=Confidence.HIGH,
        remediation="Validate untrusted input.",
        engine="opengrep",
    )

    class AdvancingAdapter:
        def scan_snapshot(self, _root: Path, _timeout: float) -> ExternalScanResult:
            now[0] = 2.0
            return ExternalScanResult(
                findings=(sample,),
                execution=ExternalExecution(
                    scanner="opengrep",
                    version="1.0.0",
                    status="completed",
                    eligible_files=("a.py", "b.py"),
                    inspected_files=("a.py", "b.py"),
                ),
            )

    monkeypatch.setattr(application_module, "OpengrepAdapter", AdvancingAdapter)

    report = scan_path(
        tmp_path,
        ScanLimits(max_processing_seconds=1.0),
        clock=lambda: now[0],
    )

    assert [item.file_path for item in report.findings] == ["a.py"]
    assert "processing_time_limit_exceeded" in report.warnings
    assert [(item.engine, item.status) for item in report.executions] == [
        ("opengrep", "completed"),
        ("python-flow", "not_run"),
        ("gitleaks", "not_run"),
        ("checkov", "not_run"),
        ("compose-policy", "not_run"),
    ]


def test_cli_imports_intelligence_through_the_owner_connection(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    cwe = tmp_path / "cwe.csv"
    cve = tmp_path / "cve.csv"
    cwe.write_text("header\n", encoding="utf-8")
    cve.write_text("header\n", encoding="utf-8")
    calls: list[tuple[object, Path, Path]] = []

    class FakeEngine:
        disposed = False

        def dispose(self) -> None:
            self.disposed = True

    engine = FakeEngine()
    monkeypatch.setattr(cli_module, "create_database_engine", lambda _url: engine)  # type: ignore[attr-defined]

    def fake_import(owner: object, cwe_path: Path, cve_path: Path) -> ImportSummary:
        calls.append((owner, cwe_path, cve_path))
        return ImportSummary(cwe_rows=2, cve_rows=3)

    monkeypatch.setattr(cli_module, "import_intelligence_data", fake_import)  # type: ignore[attr-defined]

    result = runner.invoke(
        app,
        ["import-intelligence", "--cwe", str(cwe), "--cve", str(cve)],
    )

    assert result.exit_code == 0, result.stdout
    assert result.stdout == "Imported 2 CWE rows and 3 CVE rows.\n"
    assert calls == [(engine, cwe.resolve(), cve.resolve())]
    assert engine.disposed is True


def test_cli_ingests_documents_through_the_provider_boundary(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    document = tmp_path / "guide.md"
    document.write_text("# Guide\n\nUse parameterized queries.", encoding="utf-8")
    calls: list[tuple[Path, int, int]] = []

    def fake_ingest(
        target: Path,
        _settings: object,
        chunk_size: int,
        overlap: int,
    ) -> tuple[int, int]:
        calls.append((target, chunk_size, overlap))
        return 1, 2

    monkeypatch.setattr(cli_module, "_run_document_ingestion", fake_ingest)  # type: ignore[attr-defined]

    result = runner.invoke(
        app,
        ["ingest-documents", str(document), "--chunk-size", "300", "--overlap", "30"],
    )

    assert result.exit_code == 0, result.stdout
    assert result.stdout == "Ingested 1 document as 2 chunks.\n"
    assert calls == [(document.resolve(), 300, 30)]


def test_cli_maps_document_ingestion_failure_without_content_leak(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    document = tmp_path / "guide.md"
    document.write_text("private document contents", encoding="utf-8")

    def fail_ingest(*_args: object, **_kwargs: object) -> tuple[int, int]:
        raise DocumentIngestionError("invalid_utf8", "guide.md")

    monkeypatch.setattr(cli_module, "_run_document_ingestion", fail_ingest)  # type: ignore[attr-defined]

    result = runner.invoke(app, ["ingest-documents", str(document)])

    assert result.exit_code == 1
    assert "invalid_utf8" in result.output
    assert "private document contents" not in result.output


def test_cli_corpus_sync_is_preview_only_unless_apply_is_explicit(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from security_review.intelligence.qdrant_retriever import CorpusSyncResult

    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    calls: list[tuple[Path, Path, int, int, bool, bool, Path]] = []

    def fake_sync(
        root: Path,
        manifest_path: Path,
        _settings: object,
        chunk_size: int,
        overlap: int,
        apply: bool,
        allow_empty: bool,
        receipt_path: Path,
    ) -> CorpusSyncResult:
        calls.append((root, manifest_path, chunk_size, overlap, apply, allow_empty, receipt_path))
        return CorpusSyncResult("test-corpus", (), (), 0, applied=apply)

    monkeypatch.setattr(cli_module, "_run_corpus_sync", fake_sync)  # type: ignore[attr-defined]
    preview = runner.invoke(app, ["sync-corpus", str(tmp_path), "--manifest", str(manifest)])
    applied = runner.invoke(
        app,
        [
            "sync-corpus",
            str(tmp_path),
            "--manifest",
            str(manifest),
            "--apply",
            "--allow-empty",
            "--receipt",
            str(tmp_path / "receipt.json"),
        ],
    )

    assert preview.exit_code == applied.exit_code == 0
    assert calls == [
        (
            tmp_path.resolve(),
            manifest.resolve(),
            350,
            50,
            False,
            False,
            Path("build/evidence/ingest-receipt.json"),
        ),
        (tmp_path.resolve(), manifest.resolve(), 350, 50, True, True, tmp_path / "receipt.json"),
    ]
