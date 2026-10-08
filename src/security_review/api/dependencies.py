"""Dependency boundaries for thin FastAPI route adapters."""

from __future__ import annotations

from contextlib import AbstractContextManager
from tempfile import TemporaryDirectory
from typing import Protocol, cast

from fastapi import Request

from security_review.api.errors import APIError
from security_review.application import ScanService
from security_review.config import Settings
from security_review.orchestrator.state import KnowledgeAnswer
from security_review.ports import ReportRepository


class TempDirectoryFactory(Protocol):
    """Create one context-managed private workspace per request."""

    def __call__(self) -> AbstractContextManager[str]: ...


class KnowledgeAnswerer(Protocol):
    """Application boundary exposed to the knowledge HTTP route."""

    def answer(self, question: str) -> KnowledgeAnswer: ...


def _temporary_directory() -> AbstractContextManager[str]:
    return TemporaryDirectory(prefix="secragraph-")


def get_settings(request: Request) -> Settings:
    """Return the settings owned by this application instance."""

    return cast(Settings, request.app.state.settings)


def get_scan_service(request: Request) -> ScanService:
    """Return the application scan service owned by this app."""

    return cast(ScanService, request.app.state.scan_service)


def get_knowledge_service(request: Request) -> KnowledgeAnswerer:
    """Return the app-owned knowledge service or a typed unavailable error."""

    service = getattr(request.app.state, "knowledge_service", None)
    if service is None:
        raise APIError(
            503,
            "knowledge_provider_unavailable",
            "The security knowledge provider is not configured.",
        )
    return cast(KnowledgeAnswerer, service)


def get_report_repository(request: Request) -> ReportRepository:
    """Return the repository shared by scans and report retrieval."""

    return cast(ReportRepository, request.app.state.report_repository)


def get_temp_factory() -> TempDirectoryFactory:
    """Return an injectable request-workspace factory."""

    return _temporary_directory
