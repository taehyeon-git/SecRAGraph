"""Typer command-line adapter for local and CI security reviews."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory, gettempdir
from typing import Annotated, Protocol

import typer
from sqlalchemy.exc import SQLAlchemyError

from security_review.application import UnsupportedTargetError, scan_path
from security_review.config import Settings
from security_review.container_review import scan_image_path
from security_review.domain.models import ScanReport
from security_review.history_review import scan_history_path
from security_review.intelligence.dynamic_cwe import CweEvidenceProvider
from security_review.intelligence.ingestion import (
    DocumentIngestionError,
    chunk_documents,
    load_knowledge_documents,
)
from security_review.intelligence.manifest import ManifestError, load_verified_corpus
from security_review.intelligence.osv import LiveOsvClient, OsvInputError, OsvUnavailableError
from security_review.intelligence.qdrant_retriever import CorpusSyncResult
from security_review.membership.service import MembershipError
from security_review.orchestrator.scan_graph import DependencyAuditor
from security_review.ports import IntelligenceConfigurationError, IntelligenceUnavailableError
from security_review.reporting.sarif import render_sarif
from security_review.reporting.types import ReportFormat, render_report
from security_review.scanner.files import ScanLimits
from security_review.storage.database import create_database_engine, create_session_factory
from security_review.storage.intelligence import IntelligenceImportError, import_intelligence_data

app = typer.Typer(
    name="security-review",
    help="Review source, trusted Git history and image tar, or disposable test APIs.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Run SecRAGraph's source, history, image and isolated test-API tools."""


class MembershipAdmin(Protocol):
    def register(self, username: str, password: str) -> object: ...

    def disable(self, username: str) -> None: ...

    def unlock(self, username: str) -> None: ...


@contextmanager
def _membership_service_context() -> Iterator[MembershipAdmin]:
    """Open and dispose the local account database without logging credentials."""

    from security_review.membership.service import MembershipService
    from security_review.storage.members import SqlAlchemyMembershipRepository

    settings = Settings()
    engine = create_database_engine(settings.database_url)
    try:
        sessions = create_session_factory(settings.database_url, engine=engine)
        yield MembershipService(SqlAlchemyMembershipRepository(sessions))
    finally:
        engine.dispose()


@app.command("create-user")
def create_user(username: Annotated[str, typer.Argument(help="Member username")]) -> None:
    """Create a member account; prompt for the password without terminal echo."""

    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    try:
        with _membership_service_context() as membership:
            membership.register(username, password)
    except (MembershipError, SQLAlchemyError, ValueError) as error:
        del error
        typer.echo("Could not create member account.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Member {username} created.")


@app.command("disable-user")
def disable_user(username: Annotated[str, typer.Argument(help="Member username")]) -> None:
    """Disable a member and revoke their sessions."""

    try:
        with _membership_service_context() as membership:
            membership.disable(username)
    except (MembershipError, SQLAlchemyError, ValueError) as error:
        del error
        typer.echo("Could not disable member account.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Member {username} disabled.")


@app.command("unlock-user")
def unlock_user(username: Annotated[str, typer.Argument(help="Member username")]) -> None:
    """Clear a member's failed-login lockout after local identity checks."""

    try:
        with _membership_service_context() as membership:
            membership.unlock(username)
    except (MembershipError, SQLAlchemyError, ValueError) as error:
        del error
        typer.echo("Could not unlock member account.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Member {username} unlocked.")


def _osv_client_factory() -> LiveOsvClient:
    return LiveOsvClient()


def _dependency_auditor_factory() -> DependencyAuditor:
    from security_review.intelligence.dependency_osv import LiveDependencyAuditor

    return LiveDependencyAuditor()


def _cwe_evidence_factory() -> CweEvidenceProvider:
    from security_review.intelligence.dynamic_cwe import LiveCweEvidenceProvider

    cache_root = Path(gettempdir()) / "secragraph-cwe-evidence"
    return LiveCweEvidenceProvider(cache_root)


@app.command("osv-query")
def osv_query(
    ecosystem: Annotated[str, typer.Option("--ecosystem")],
    package: Annotated[str, typer.Option("--package")],
    version: Annotated[str, typer.Option("--version")],
) -> None:
    """Fetch OSV advisories and CVE identifiers for a named package version."""

    try:
        result = _osv_client_factory().query_package(ecosystem, package, version)
    except OsvInputError as error:
        typer.echo("The package query is invalid.", err=True)
        raise typer.Exit(code=2) from error
    except OsvUnavailableError as error:
        typer.echo("OSV vulnerability data is unavailable.", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(json.dumps(asdict(result), ensure_ascii=False))


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


def scan_dast_container(
    container: str,
    port: int,
    openapi_path: str,
    *,
    auth_header_env: str | None = None,
    active: bool = False,
) -> ScanReport:
    """Use the DAST service without loading Docker code for other CLI commands."""

    from security_review.dast.application import scan_dast_container as run

    return run(
        container,
        port,
        openapi_path,
        auth_header_env=auth_header_env,
        active=active,
        cwe_evidence=_cwe_evidence_factory(),
    )


@app.command("dast")
def dast(
    container: Annotated[
        str, typer.Argument(help="Running Docker container labelled as a disposable test API")
    ],
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8000,
    openapi_path: Annotated[str, typer.Option("--openapi-path")] = "/openapi.json",
    auth_header_env: Annotated[str | None, typer.Option("--auth-header-env")] = None,
    active: Annotated[
        bool,
        typer.Option("--active", help="Actively probe an expressly permitted disposable container"),
    ] = False,
    report_format: Annotated[
        ReportFormat, typer.Option("--format", case_sensitive=False)
    ] = ReportFormat.MARKDOWN,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Inspect a disposable test API with passive or explicit active ZAP."""

    try:
        report = scan_dast_container(
            container,
            port,
            openapi_path,
            auth_header_env=auth_header_env,
            active=active,
        )
    except ValueError as error:
        del error
        typer.echo("DAST target or scan configuration is invalid.", err=True)
        raise typer.Exit(code=2) from None
    rendered = render_report(report, report_format)
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        try:
            _write_atomically(output, rendered)
        except OSError as error:
            typer.echo(f"Could not write report: {error}", err=True)
            raise typer.Exit(code=1) from error
    if any(item.status not in {"completed", "skipped"} for item in report.executions):
        raise typer.Exit(code=1)


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
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Scan TARGET and write JSON, Markdown, or SARIF."""

    try:
        report = scan_path(
            target,
            ScanLimits(),
            dependency_auditor=None if offline else _dependency_auditor_factory(),
            cwe_evidence=None if offline else _cwe_evidence_factory(),
        )
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


@app.command("scan-history")
def scan_history(
    root: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
            help="Trusted local Git checkout",
        ),
    ],
    base_sha: Annotated[
        str | None, typer.Option("--base", help="Exclusive full commit SHA")
    ] = None,
    head_sha: Annotated[
        str | None, typer.Option("--head", help="Inclusive full commit SHA")
    ] = None,
    report_format: Annotated[
        ReportFormat, typer.Option("--format", case_sensitive=False)
    ] = ReportFormat.MARKDOWN,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Scan selected Git history for redacted secret candidates."""

    try:
        report = scan_history_path(root, base_sha=base_sha, head_sha=head_sha)
    except ValueError:
        typer.echo("Git history scan selection is invalid.", err=True)
        raise typer.Exit(code=2) from None
    rendered = render_report(report, report_format)
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        try:
            _write_atomically(output, rendered)
        except OSError as error:
            typer.echo("Could not write history report.", err=True)
            raise typer.Exit(code=1) from error
    if len(report.executions) != 1:
        raise typer.Exit(code=1)
    execution = report.executions[0]
    if (
        execution.engine != "gitleaks-history"
        or execution.kind != "secret"
        or execution.status != "completed"
        or execution.version != "8.30.1"
        or execution.revision_head is None
        or execution.selected_commit_count is None
        or execution.selected_commit_count < 1
        or execution.checks != ("git-history", "builtin-default")
    ):
        raise typer.Exit(code=1)
    if report.findings:
        raise typer.Exit(code=3)


@app.command("scan-image")
def scan_image(
    tar_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Trusted local OCI/Docker image tar; never a member upload",
        ),
    ],
    image_id: Annotated[str, typer.Option("--image-id", help="Exact local Docker image ID")],
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Trivy cache with a fresh downloaded DB")
    ],
    output_dir: Annotated[
        Path, typer.Option("--output-dir", help="New directory for normalized image evidence")
    ],
    trivy_binary: Annotated[str, typer.Option("--trivy-binary")] = "trivy",
    offline_evidence: Annotated[
        bool, typer.Option("--offline-evidence", help="Do not fetch CWE evidence")
    ] = False,
) -> None:
    """Scan a trusted image tar without building or pulling any image."""

    from security_review.container_image import ImageScanError
    from security_review.orchestrator.scan_graph import ScanWorkflowError

    if output_dir.exists():
        typer.echo("Image evidence output directory already exists.", err=True)
        raise typer.Exit(code=2)
    try:
        review = scan_image_path(
            tar_path,
            expected_local_id=image_id,
            trivy_binary=trivy_binary,
            cache_dir=cache_dir,
            cwe_evidence=None if offline_evidence else _cwe_evidence_factory(),
        )
    except ImageScanError as error:
        typer.echo(f"Image scan failed: {error}", err=True)
        raise typer.Exit(code=1) from None
    except ScanWorkflowError:
        typer.echo("Image report workflow failed.", err=True)
        raise typer.Exit(code=1) from None

    report = review.report
    if len(report.executions) != 1:
        typer.echo("Image scan did not complete.", err=True)
        raise typer.Exit(code=1)
    execution = report.executions[0]
    if (
        execution.kind != "container"
        or execution.status != "completed"
        or execution.image_id is None
        or execution.image_local_id is None
        or execution.image_tar_sha256 is None
        or execution.image_db_updated_at is None
        or execution.sbom_sha256 is None
        or execution.sbom_component_count is None
        or execution.sbom_component_count < 1
        or sha256(review.sbom_bytes).hexdigest() != execution.sbom_sha256
    ):
        typer.echo("Image scan did not complete.", err=True)
        raise typer.Exit(code=1)

    artifacts = {
        "container.json": render_report(report, ReportFormat.JSON).encode("utf-8"),
        "container.md": render_report(report, ReportFormat.MARKDOWN).encode("utf-8"),
        "container.sarif": render_report(report, ReportFormat.SARIF).encode("utf-8"),
        "container.cdx.json": review.sbom_bytes,
    }
    manifest = {
        "schema_version": 1,
        "execution_status": execution.status,
        "trivy_version": execution.version,
        "image_id": execution.image_id,
        "image_local_id": execution.image_local_id,
        "image_tar_sha256": execution.image_tar_sha256,
        "db_updated_at": execution.image_db_updated_at.isoformat(),
        "image_vulnerability_count": execution.image_vulnerability_count,
        "image_config_count": execution.image_config_count,
        "sbom_sha256": execution.sbom_sha256,
        "sbom_component_count": execution.sbom_component_count,
        "gate_identities": [asdict(identity) for identity in review.gate_identities],
        "artifacts": {name: sha256(content).hexdigest() for name, content in artifacts.items()},
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        parent = output_dir.parent.resolve()
        with TemporaryDirectory(prefix=".sr-image-", dir=parent) as temporary:
            stage = Path(temporary)
            if stage.resolve().parent != parent:
                raise OSError("unsafe image evidence staging directory")
            for name, content in artifacts.items():
                (stage / name).write_bytes(content)
            (stage / "container.manifest.json").write_bytes(manifest_bytes)
            if output_dir.exists():
                raise FileExistsError("image evidence output directory already exists")
            stage.rename(output_dir)
    except OSError:
        typer.echo("Could not write image evidence.", err=True)
        raise typer.Exit(code=1) from None
    typer.echo("Image evidence written.")


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


class _PreviewEmbeddings:
    """Dimension-only adapter; preview and empty deletion never call a provider."""

    def __init__(self, dimension: int) -> None:
        self.dimension = dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        del texts
        raise IntelligenceConfigurationError("embedding is unavailable in preview mode")


@app.command("sync-corpus")
def sync_corpus_command(
    root: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, file_okay=False, resolve_path=True),
    ],
    manifest: Annotated[
        Path | None,
        typer.Option("--manifest", exists=True, readable=True, dir_okay=False, resolve_path=True),
    ] = None,
    chunk_size: Annotated[int, typer.Option("--chunk-size", min=1, max=2_000)] = 350,
    overlap: Annotated[int, typer.Option("--overlap", min=0, max=500)] = 50,
    apply: Annotated[bool, typer.Option("--apply")] = False,
    allow_empty: Annotated[bool, typer.Option("--allow-empty")] = False,
    receipt: Annotated[Path, typer.Option("--receipt")] = Path(
        "build/evidence/ingest-receipt.json"
    ),
) -> None:
    """Preview or apply a manifest-verified managed Qdrant corpus refresh."""

    if allow_empty and not apply:
        typer.echo("--allow-empty requires --apply", err=True)
        raise typer.Exit(code=2)
    manifest_path = manifest if manifest is not None else root / "manifest.json"
    try:
        result = _run_corpus_sync(
            root, manifest_path, Settings(), chunk_size, overlap, apply, allow_empty, receipt
        )
    except (ManifestError, DocumentIngestionError) as error:
        typer.echo(f"Corpus sync failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    except (IntelligenceConfigurationError, IntelligenceUnavailableError, ValueError):
        typer.echo("Corpus sync failed: invalid configuration or provider operation", err=True)
        raise typer.Exit(code=1) from None
    except OSError:
        typer.echo(
            "Corpus sync may have applied, but its local receipt could not be written", err=True
        )
        raise typer.Exit(code=1) from None
    action = "Applied" if result.applied else "Previewed"
    typer.echo(
        f"{action} corpus {result.corpus_id}: "
        f"{len(result.desired_document_ids)} desired documents, "
        f"{len(result.stale_document_ids)} stale documents."
    )


def _run_corpus_sync(
    root: Path,
    manifest_path: Path,
    settings: Settings,
    chunk_size: int,
    overlap: int,
    apply: bool,
    allow_empty: bool,
    receipt_path: Path = Path("build/evidence/ingest-receipt.json"),
) -> CorpusSyncResult:
    """Validate the immutable corpus before constructing any write-capable provider."""

    from qdrant_client import QdrantClient

    from security_review.intelligence.openai_adapters import OpenAIEmbeddingAdapter
    from security_review.intelligence.qdrant_retriever import QdrantDocumentRetriever

    corpus = load_verified_corpus(root, manifest_path)
    chunks = chunk_documents(corpus.documents, chunk_size, overlap)
    if (
        apply
        and chunks
        and (
            settings.openai_api_key is None
            or not settings.openai_api_key.get_secret_value().strip()
        )
    ):
        raise IntelligenceConfigurationError("openai_api_key is required for corpus apply")
    embeddings = (
        OpenAIEmbeddingAdapter.from_openai(
            api_key=settings.openai_api_key,
            model=settings.openai_embedding_model,
            dimension=settings.qdrant_vector_dimension,
        )
        if apply and chunks and settings.openai_api_key is not None
        else _PreviewEmbeddings(settings.qdrant_vector_dimension)
    )
    client = QdrantClient(
        url=settings.qdrant_url,
        api_key=settings.qdrant_api_key.get_secret_value() if settings.qdrant_api_key else None,
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
        if apply:
            retriever.ensure_collection()
        else:
            retriever.check_ready()
        result = retriever.sync_corpus(
            corpus.corpus_id, chunks, apply=apply, allow_empty=allow_empty
        )
    finally:
        client.close()
    if result.applied:
        receipt = {
            "corpus_id": corpus.corpus_id,
            "manifest_sha256": corpus.manifest_sha256,
            "documents": [
                {
                    "path": entry.path,
                    "source_url": entry.source_url,
                    "publisher": entry.publisher,
                    "license": entry.license,
                    "source_revision": entry.source_revision,
                    "source_date": entry.source_date,
                    "sha256": entry.sha256,
                }
                for entry in corpus.entries
            ],
            "desired_document_count": len(result.desired_document_ids),
            "stale_document_count": len(result.stale_document_ids),
            "chunk_count": len(chunks),
        }
        _write_atomically(receipt_path, json.dumps(receipt, indent=2))
    return result


if __name__ == "__main__":
    app()
