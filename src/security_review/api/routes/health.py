"""Dependency-independent liveness and injected readiness routes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from qdrant_client import QdrantClient
from qdrant_client.http import models
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

router = APIRouter(prefix="/health", tags=["health"])


class ReadinessProbe(Protocol):
    """Checks required infrastructure without coupling routes to implementations."""

    def check(self) -> Mapping[str, bool]: ...


class ReadinessResponse(BaseModel):
    status: str
    dependencies: dict[str, bool]
    reasons: dict[str, str] = Field(default_factory=dict)


class DefaultReadinessProbe:
    """Conservative probe used until database infrastructure is wired."""

    def __init__(self, *, testing: bool) -> None:
        self._testing = testing

    def check(self) -> Mapping[str, bool]:
        return {"postgres": self._testing}


class DatabaseReadinessProbe:
    """Require a live database with the migrated report schema."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def check(self) -> Mapping[str, bool]:
        dependencies, _ = self.check_with_reasons()
        return dependencies

    def check_with_reasons(self) -> tuple[dict[str, bool], dict[str, str]]:
        try:
            with self._engine.connect() as connection:
                schema_ready = bool(
                    connection.execute(
                        text("SELECT to_regclass('app.scan_reports') IS NOT NULL")
                    ).scalar_one()
                )
        except SQLAlchemyError:
            return {"postgres": False}, {"postgres": "connection_failed"}
        return (
            ({"postgres": True}, {})
            if schema_ready
            else ({"postgres": False}, {"postgres": "schema_missing"})
        )


class QdrantReadinessProbe:
    """Read only the collection contract without calling an embedding provider."""

    def __init__(self, client: QdrantClient, collection: str, dimension: int) -> None:
        self._client = client
        self._collection = collection
        self._dimension = dimension

    def check_with_reasons(self) -> tuple[dict[str, bool], dict[str, str]]:
        try:
            information = self._client.get_collection(self._collection)
        except Exception as error:
            status_code = getattr(error, "status_code", None)
            reason = "collection_missing" if status_code == 404 else "connection_failed"
            return {"qdrant": False}, {"qdrant": reason}
        try:
            vectors = information.config.params.vectors
            if not isinstance(vectors, models.VectorParams):
                reason = "dimension_mismatch"
            elif vectors.size != self._dimension:
                reason = "dimension_mismatch"
            elif vectors.distance != models.Distance.COSINE:
                reason = "distance_mismatch"
            else:
                return {"qdrant": True}, {}
        except (AttributeError, TypeError, ValueError):
            reason = "dimension_mismatch"
        return {"qdrant": False}, {"qdrant": reason}

    def check(self) -> Mapping[str, bool]:
        dependencies, _ = self.check_with_reasons()
        return dependencies


class CompositeReadinessProbe:
    """Probe PostgreSQL and Qdrant independently for one readiness request."""

    def __init__(self, postgres: DatabaseReadinessProbe, qdrant: QdrantReadinessProbe) -> None:
        self._postgres = postgres
        self._qdrant = qdrant

    def check_with_reasons(self) -> tuple[dict[str, bool], dict[str, str]]:
        postgres, postgres_reasons = self._postgres.check_with_reasons()
        qdrant, qdrant_reasons = self._qdrant.check_with_reasons()
        return postgres | qdrant, postgres_reasons | qdrant_reasons

    def check(self) -> Mapping[str, bool]:
        dependencies, _ = self.check_with_reasons()
        return dependencies


def get_readiness_probe(request: Request) -> ReadinessProbe:
    return cast(ReadinessProbe, request.app.state.readiness_probe)


@router.get("/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", response_model=ReadinessResponse)
def readiness(
    probe: Annotated[ReadinessProbe, Depends(get_readiness_probe)],
) -> JSONResponse:
    detailed_check = getattr(probe, "check_with_reasons", None)
    if callable(detailed_check):
        dependencies, reasons = detailed_check()
    else:
        dependencies, reasons = dict(probe.check()), {}
    body = ReadinessResponse(
        status="ok" if all(dependencies.values()) else "unavailable",
        dependencies=dependencies,
        reasons=reasons,
    )
    status_code = 200 if all(dependencies.values()) else 503
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))
