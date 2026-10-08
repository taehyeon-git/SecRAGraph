"""Typer command-line adapter for local and CI security reviews."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Annotated

import typer

from security_review.application import UnsupportedTargetError, scan_path
from security_review.config import Settings
from security_review.intelligence.ingestion import (
    DocumentIngestionError,
    chunk_documents,
    load_knowledge_documents,
)
from security_review.ports import IntelligenceConfigurationError, IntelligenceUnavailableError
from security_review.reporting.sarif import render_sarif
from security_review.reporting.types import ReportFormat, render_report
from security_review.scanner.files import ScanLimits
from security_review.storage.database import create_database_engine
from security_review.storage.intelligence import IntelligenceImportError, import_intelligence_data

app = typer.Typer(
    name="security-review",
    help="Scan source code without executing it and render a canonical security report.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Run SecRAGraph's local, non-executing security review tools."""


def _write_atomically(output: Path, rendered: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".sr-",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as handle:
            handle.write(rendered)
            temporary = Path(handle.name)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, resolve_path=True),
    ],
    report_format: Annotated[
        ReportFormat,
        typer.Option("--format", case_sensitive=False),
    ] = ReportFormat.MARKDOWN,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Scan TARGET and write JSON, Markdown, or SARIF."""

    try:
        report = scan_path(target, ScanLimits())
    except UnsupportedTargetError as error:
        raise typer.BadParameter(str(error), param_hint="TARGET") from error
    if report_format is ReportFormat.SARIF:
        source_root = target if target.is_dir() else target.parent
        try:
            prefix = source_root.relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            prefix = ""
        rendered = render_sarif(report, path_prefix=prefix)
    else:
        rendered = render_report(report, report_format)
    if output is None:
        typer.echo(rendered, nl=False)
        return
    try:
        _write_atomically(output, rendered)
    except OSError as error:
        typer.echo(f"Could not write report: {error}", err=True)
        raise typer.Exit(code=1) from error


@app.command("import-intelligence")
def import_intelligence(
    cwe: Annotated[
        Path,
        typer.Option("--cwe", exists=True, readable=True, dir_okay=False, resolve_path=True),
    ],
    cve: Annotated[
        Path,
        typer.Option("--cve", exists=True, readable=True, dir_okay=False, resolve_path=True),
    ],
) -> None:
    """Validate and atomically upsert CWE and CVE CSV files."""

    settings = Settings()
    engine = create_database_engine(settings.database_url)
    try:
        summary = import_intelligence_data(engine, cwe, cve)
    except IntelligenceImportError as error:
        typer.echo(f"Import failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    finally:
        engine.dispose()
    typer.echo(f"Imported {summary.cwe_rows} CWE rows and {summary.cve_rows} CVE rows.")


@app.command("bootstrap-qdrant")
def bootstrap_qdrant() -> None:
    """Create the configured local collection without an OpenAI credential."""

    from qdrant_client import QdrantClient

    from security_review.intelligence.qdrant_retriever import bootstrap_collection

    settings = Settings()
    client = QdrantClient(
        url=settings.qdrant_url,
        api_key=(settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None),
        timeout=5,
        prefer_grpc=False,
    )
    try:
        bootstrap_collection(
            client,
            settings.qdrant_collection,
            settings.qdrant_vector_dimension,
        )
    except (IntelligenceConfigurationError, IntelligenceUnavailableError) as error:
        typer.echo(f"Qdrant bootstrap failed: {error.reason}", err=True)
        raise typer.Exit(code=1) from error
    finally:
        client.close()
    typer.echo("Qdrant collection is ready.")


@app.command("ingest-documents")
def ingest_documents_command(
    target: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, resolve_path=False),
    ],
    chunk_size: Annotated[
        int,
        typer.Option("--chunk-size", min=1, max=2_000),
    ] = 350,
    overlap: Annotated[
        int,
        typer.Option("--overlap", min=0, max=500),
    ] = 50,
) -> None:
    """Chunk UTF-8 Markdown and index it in the configured Qdrant collection."""

    try:
        document_count, chunk_count = _run_document_ingestion(
            target,
            Settings(),
            chunk_size,
            overlap,
        )
    except (
        DocumentIngestionError,
        IntelligenceConfigurationError,
        IntelligenceUnavailableError,
    ) as error:
        typer.echo(f"Ingestion failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    except ValueError as error:
        typer.echo("Ingestion failed: invalid configuration or chunk options", err=True)
        raise typer.Exit(code=1) from error
    document_label = "document" if document_count == 1 else "documents"
    chunk_label = "chunk" if chunk_count == 1 else "chunks"
    typer.echo(f"Ingested {document_count} {document_label} as {chunk_count} {chunk_label}.")


def _run_document_ingestion(
    target: Path,
    settings: Settings,
    chunk_size: int,
    overlap: int,
) -> tuple[int, int]:
    """Build provider adapters, ingest one bounded corpus, and always close the client."""

    if settings.openai_api_key is None:
        raise IntelligenceConfigurationError("openai_api_key is required for document ingestion")

    from qdrant_client import QdrantClient

    from security_review.intelligence.openai_adapters import OpenAIEmbeddingAdapter
    from security_review.intelligence.qdrant_retriever import QdrantDocumentRetriever

    documents = load_knowledge_documents(target)
    chunks = chunk_documents(documents, chunk_size, overlap)
    embeddings = OpenAIEmbeddingAdapter.from_openai(
        api_key=settings.openai_api_key,
        model=settings.openai_embedding_model,
        dimension=settings.qdrant_vector_dimension,
    )
    qdrant_api_key = settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None
    client = QdrantClient(
        url=settings.qdrant_url,
        api_key=qdrant_api_key,
        prefer_grpc=False,
        timeout=10,
    )
    try:
        retriever = QdrantDocumentRetriever(
            client,
            embeddings,
            settings.qdrant_collection,
            min_score=settings.qdrant_min_score,
            max_search_limit=settings.qdrant_search_limit,
        )
        retriever.ensure_collection()
        chunk_count = retriever.replace_documents(chunks)
    finally:
        client.close()
    return len(documents), chunk_count


if __name__ == "__main__":
    app()
