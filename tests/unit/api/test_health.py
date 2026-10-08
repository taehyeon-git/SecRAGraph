from collections.abc import Mapping
from contextlib import AbstractContextManager
from types import SimpleNamespace, TracebackType
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from qdrant_client.http import models
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from security_review.api.app import create_app
from security_review.api.routes.health import (
    CompositeReadinessProbe,
    DatabaseReadinessProbe,
    QdrantReadinessProbe,
    get_readiness_probe,
)
from security_review.config import Settings


class FakeProbe:
    def __init__(self, dependencies: Mapping[str, bool]) -> None:
        self._dependencies = dependencies

    def check(self) -> Mapping[str, bool]:
        return self._dependencies


class FakeScalarResult:
    def __init__(self, value: bool) -> None:
        self._value = value

    def scalar_one(self) -> bool:
        return self._value


class FakeConnection(AbstractContextManager["FakeConnection"]):
    def __init__(self, schema_ready: bool) -> None:
        self._schema_ready = schema_ready

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback

    def execute(self, statement: object) -> FakeScalarResult:
        del statement
        return FakeScalarResult(self._schema_ready)


class FakeEngine:
    def __init__(self, *, schema_ready: bool = True, fails: bool = False) -> None:
        self._schema_ready = schema_ready
        self._fails = fails

    def connect(self) -> Any:
        if self._fails:
            raise SQLAlchemyError("database unavailable")
        return FakeConnection(self._schema_ready)


def test_liveness_does_not_require_dependencies() -> None:
    client = TestClient(create_app(Settings(testing=True)))

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_is_503_when_postgres_is_down() -> None:
    app = create_app(Settings(testing=True))
    app.dependency_overrides[get_readiness_probe] = lambda: FakeProbe(
        {"postgres": False, "qdrant": True}
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "dependencies": {"postgres": False, "qdrant": True},
        "reasons": {},
    }


def test_readiness_is_ok_only_when_every_dependency_is_ready() -> None:
    app = create_app(Settings(testing=True))
    app.dependency_overrides[get_readiness_probe] = lambda: FakeProbe(
        {"postgres": True, "qdrant": True}
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_database_readiness_requires_the_migrated_report_table() -> None:
    ready = DatabaseReadinessProbe(cast(Engine, FakeEngine(schema_ready=True)))
    missing = DatabaseReadinessProbe(cast(Engine, FakeEngine(schema_ready=False)))
    unavailable = DatabaseReadinessProbe(cast(Engine, FakeEngine(fails=True)))

    assert ready.check() == {"postgres": True}
    assert missing.check() == {"postgres": False}
    assert unavailable.check() == {"postgres": False}


class FakeCollectionClient:
    def __init__(
        self,
        *,
        size: int = 3,
        distance: models.Distance = models.Distance.COSINE,
        error: Exception | None = None,
    ) -> None:
        self.size = size
        self.distance = distance
        self.error = error

    def get_collection(self, name: str) -> Any:
        if self.error:
            raise self.error
        return SimpleNamespace(
            config=SimpleNamespace(
                params=SimpleNamespace(
                    vectors=models.VectorParams(size=self.size, distance=self.distance)
                )
            )
        )


def test_composite_readiness_reports_independent_safe_reasons() -> None:
    probe = CompositeReadinessProbe(
        DatabaseReadinessProbe(cast(Engine, FakeEngine(fails=True))),
        QdrantReadinessProbe(cast(Any, FakeCollectionClient(size=2)), "security", 3),
    )

    dependencies, reasons = probe.check_with_reasons()

    assert dependencies == {"postgres": False, "qdrant": False}
    assert reasons == {"postgres": "connection_failed", "qdrant": "dimension_mismatch"}


def test_qdrant_readiness_checks_collection_without_mutating_it() -> None:
    client = FakeCollectionClient()
    probe = QdrantReadinessProbe(cast(Any, client), "security", 3)

    assert probe.check_with_reasons() == ({"qdrant": True}, {})


def test_readiness_response_never_exposes_provider_exception_text() -> None:
    app = create_app(Settings(testing=True))
    app.state.readiness_probe = CompositeReadinessProbe(
        DatabaseReadinessProbe(cast(Engine, FakeEngine(schema_ready=True))),
        QdrantReadinessProbe(
            cast(Any, FakeCollectionClient(error=OSError("secret@private-host"))),
            "security",
            3,
        ),
    )

    response = TestClient(app).get("/health/ready")

    assert response.status_code == 503
    assert response.json()["dependencies"] == {"postgres": True, "qdrant": False}
    assert response.json()["reasons"] == {"qdrant": "connection_failed"}
    assert "secret@private-host" not in response.text


@pytest.mark.parametrize(
    ("client", "reason"),
    [
        (FakeCollectionClient(distance=models.Distance.DOT), "distance_mismatch"),
        (
            FakeCollectionClient(
                error=type("MissingCollection", (Exception,), {"status_code": 404})()
            ),
            "collection_missing",
        ),
    ],
)
def test_qdrant_readiness_reasons_are_fixed_contract_codes(
    client: FakeCollectionClient, reason: str
) -> None:
    probe = QdrantReadinessProbe(cast(Any, client), "security", 3)

    assert probe.check_with_reasons() == ({"qdrant": False}, {"qdrant": reason})
