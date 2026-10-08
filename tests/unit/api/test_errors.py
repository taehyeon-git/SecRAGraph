from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_review.api.app import create_app
from security_review.config import Settings


def test_unknown_route_has_stable_error_shape() -> None:
    response = TestClient(create_app(Settings(testing=True))).get("/v1/missing")

    assert response.status_code == 404
    body = response.json()
    assert body["code"] == "not_found"
    assert body["message"] == "Resource not found."
    UUID(body["correlation_id"])
    assert response.headers["x-correlation-id"] == body["correlation_id"]


def test_validation_error_has_stable_shape() -> None:
    app = create_app(Settings(testing=True))

    @app.get("/requires-int/{value}")
    def requires_int(value: int) -> dict[str, int]:
        return {"value": value}

    response = TestClient(app).get("/requires-int/not-an-int")

    assert response.status_code == 422
    body = response.json()
    assert set(body) >= {"code", "message", "correlation_id", "details"}
    assert body["code"] == "validation_error"
    assert isinstance(body["details"], list)


def test_valid_incoming_correlation_id_is_echoed() -> None:
    correlation_id = str(uuid4())

    response = TestClient(create_app(Settings(testing=True))).get(
        "/health/live",
        headers={"X-Correlation-ID": correlation_id},
    )

    assert response.headers["x-correlation-id"] == correlation_id


def test_internal_error_does_not_expose_exception_text() -> None:
    app: FastAPI = create_app(Settings(testing=True))

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("database-password-should-not-leak")

    response = TestClient(app, raise_server_exceptions=False).get("/boom")

    assert response.status_code == 500
    assert response.json()["code"] == "internal_error"
    assert "database-password" not in response.text
