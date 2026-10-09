import json
from pathlib import Path

from typer.testing import CliRunner

import security_review.application as application_module
import security_review.cli as cli_module
from security_review.application import scan_path
from security_review.cli import app
from security_review.intelligence.ingestion import DocumentIngestionError
from security_review.scanner.files import ScanLimits
from security_review.storage.intelligence import ImportSummary

runner = CliRunner()


def test_cli_writes_json_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["scan", "examples/insecure", "--format", "json", "--output", str(output)],
    )

    assert result.exit_code == 0, result.stdout
    rendered = output.read_text(encoding="utf-8")
    payload = json.loads(rendered)
    assert payload["summary"]["total"] >= 3
    assert "demo-not-a-real-secret-12345" not in rendered


def test_cli_creates_parent_directory_for_sarif_output(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "sample.sarif"

    result = runner.invoke(
        app,
        ["scan", "examples/insecure", "--format", "sarif", "--output", str(output)],
    )

    assert result.exit_code == 0, result.stdout
    assert json.loads(output.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_sarif_locations_are_relative_to_invocation_directory(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("eval('unsafe')", encoding="utf-8")
    output = tmp_path / "scan.sarif"
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


def test_scan_stops_with_stable_warning_after_deadline(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    (tmp_path / "a.py").write_text("eval(first)", encoding="utf-8")
    (tmp_path / "b.py").write_text("eval(second)", encoding="utf-8")
    now = [0.0]
    original_scan_text_detailed = application_module.scan_text_detailed

    def advancing_scan(*args: object, **kwargs: object) -> object:
        result = original_scan_text_detailed(*args, **kwargs)  # type: ignore[arg-type]
        now[0] = 2.0
        return result

    monkeypatch.setattr(application_module, "scan_text_detailed", advancing_scan)  # type: ignore[attr-defined]

    report = scan_path(
        tmp_path,
        ScanLimits(max_processing_seconds=1.0),
        clock=lambda: now[0],
    )

    assert [item.file_path for item in report.findings] == ["a.py"]
    assert "processing_time_limit_exceeded" in report.warnings


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
