"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from qdrant_client import QdrantClient
from sqlalchemy import Engine
from starlette.middleware.base import RequestResponseEndpoint

from security_review import __version__
from security_review.api.dependencies import KnowledgeAnswerer
from security_review.api.errors import register_error_handlers
from security_review.api.middleware import RequestBodyLimitMiddleware, correlation_id
from security_review.api.routes.health import (
    CompositeReadinessProbe,
    DatabaseReadinessProbe,
    DefaultReadinessProbe,
    QdrantReadinessProbe,
    ReadinessProbe,
)
from security_review.api.routes.health import router as health_router
from security_review.api.routes.knowledge import router as knowledge_router
from security_review.api.routes.reports import router as reports_router
from security_review.api.routes.scans import router as scans_router
from security_review.application import ScanService
from security_review.config import Settings
from security_review.intelligence.openai_adapters import OpenAIChatAdapter, OpenAIEmbeddingAdapter
from security_review.intelligence.qdrant_retriever import QdrantDocumentRetriever
from security_review.intelligence.text2sql import Text2SqlService
from security_review.observability import bind_audit_sink, bind_context, configure_logging
from security_review.orchestrator.knowledge_graph import (
    KnowledgeService,
    KnowledgeServices,
    build_knowledge_graph,
)
from security_review.orchestrator.scan_graph import ScanGraphServices
from security_review.ports import ChatModel, EmbeddingModel, ReportRepository
from security_review.storage import (
    InMemoryReportRepository,
    SqlAlchemyReportRepository,
    create_database_engine,
    create_session_factory,
)
from security_review.storage.audit import PostgresAuditSink


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        for name in ("database_engine", "intelligence_engine"):
            engine = getattr(app.state, name, None)
            if isinstance(engine, Engine):
                engine.dispose()
        client = getattr(app.state, "qdrant_client", None)
        if isinstance(client, QdrantClient) and getattr(app.state, "owns_qdrant_client", False):
            client.close()


def create_app(
    settings: Settings | None = None,
    *,
    reports: ReportRepository | None = None,
    knowledge_service: KnowledgeAnswerer | None = None,
    chat_model: ChatModel | None = None,
    embeddings: EmbeddingModel | None = None,
    qdrant_client: QdrantClient | None = None,
) -> FastAPI:
    """Create an isolated API instance for production or tests."""

    configured = settings or Settings()
    configure_logging(configured.environment)
    app = FastAPI(title="SecRAGraph", version=__version__, lifespan=_lifespan)
    app.state.settings = configured
    app.state.audit_sink = None
    report_repository = reports
    readiness_probe: ReadinessProbe = DefaultReadinessProbe(testing=configured.testing)
    if report_repository is None and configured.testing:
        report_repository = InMemoryReportRepository()
    if report_repository is None:
        engine = create_database_engine(configured.database_url)
        sessions = create_session_factory(configured.database_url, engine=engine)
        app.state.database_engine = engine
        report_repository = SqlAlchemyReportRepository(sessions)
        app.state.audit_sink = PostgresAuditSink(sessions)
        readiness_probe = DatabaseReadinessProbe(engine)
    if not configured.testing or (chat_model is not None and embeddings is not None):
        if qdrant_client is None:
            qdrant_client = QdrantClient(
                url=configured.qdrant_url,
                api_key=(
                    configured.qdrant_api_key.get_secret_value()
                    if configured.qdrant_api_key
                    else None
                ),
                prefer_grpc=False,
                timeout=3,
            )
            app.state.owns_qdrant_client = True
        app.state.qdrant_client = qdrant_client
        if isinstance(readiness_probe, DatabaseReadinessProbe):
            readiness_probe = CompositeReadinessProbe(
                readiness_probe,
                QdrantReadinessProbe(
                    qdrant_client,
                    configured.qdrant_collection,
                    configured.qdrant_vector_dimension,
                ),
            )
    app.state.readiness_probe = readiness_probe
    app.state.report_repository = report_repository
    scan_graph_services: ScanGraphServices | None = None
    if configured.intelligence_database_url and qdrant_client is not None:
        has_openai_key = bool(
            configured.openai_api_key and configured.openai_api_key.get_secret_value().strip()
        )
        if chat_model is None and has_openai_key and configured.openai_api_key is not None:
            chat_model = OpenAIChatAdapter.from_openai(
                api_key=configured.openai_api_key,
                model=configured.openai_chat_model,
            )
        if embeddings is None and has_openai_key and configured.openai_api_key is not None:
            embeddings = OpenAIEmbeddingAdapter.from_openai(
                api_key=configured.openai_api_key,
                model=configured.openai_embedding_model,
                dimension=configured.qdrant_vector_dimension,
            )
        if chat_model is not None and embeddings is not None:
            from security_review.storage.intelligence import PostgresSecurityKnowledgeRepository

            reader_engine = create_database_engine(configured.intelligence_database_url)
            app.state.intelligence_engine = reader_engine
            retriever = QdrantDocumentRetriever(
                qdrant_client,
                embeddings,
                configured.qdrant_collection,
                min_score=configured.qdrant_min_score,
                max_search_limit=configured.qdrant_search_limit,
            )
            repository = PostgresSecurityKnowledgeRepository(
                reader_engine.connect,
                row_limit=configured.sql_row_limit,
                statement_timeout_ms=configured.sql_statement_timeout_ms,
            )
            text2sql = Text2SqlService(
                sql_model=chat_model,
                answer_model=chat_model,
                repository=repository,
                max_attempts=configured.max_sql_attempts,
                row_limit=configured.sql_row_limit,
            )
            if knowledge_service is None:
                knowledge_service = KnowledgeService(
                    build_knowledge_graph(
                        KnowledgeServices(
                            chat_model=chat_model,
                            text2sql=text2sql,
                            retriever=retriever,
                            max_rag_attempts=configured.max_rag_attempts,
                        )
                    )
                )
            scan_graph_services = ScanGraphServices(retriever=retriever, chat_model=chat_model)
    app.state.scan_service = ScanService(report_repository, graph_services=scan_graph_services)
    app.state.knowledge_service = knowledge_service

    @app.middleware("http")
    async def add_correlation_id(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_correlation_id = getattr(request.state, "correlation_id", None)
        if request_correlation_id is None:
            request_correlation_id = correlation_id(request.headers.get("X-Correlation-ID"))
            request.state.correlation_id = request_correlation_id
        with bind_context(request_correlation_id, None), bind_audit_sink(app.state.audit_sink):
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = request_correlation_id
        return response

    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=configured.max_request_bytes)

    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(knowledge_router)
    app.include_router(scans_router)
    app.include_router(reports_router)
    return app
