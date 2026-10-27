from __future__ import annotations

import importlib

from sqlalchemy import create_engine, text


def test_legacy_evidence_is_replaced_without_changing_finding_identity(monkeypatch) -> None:
    migration = importlib.import_module("migrations.versions.20261018_0004_safe_evidence")
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS app")
        connection.exec_driver_sql(
            "CREATE TABLE app.findings (finding_id TEXT, redacted_evidence TEXT, message TEXT)"
        )
        connection.execute(
            text(
                "INSERT INTO app.findings (finding_id, redacted_evidence, message) "
                "VALUES (:id, :evidence, :message)"
            ),
            {
                "id": "OG:stable",
                "evidence": "eval(value) # opaque-canary-12345",
                "message": "Static message",
            },
        )
        monkeypatch.setattr(migration.op, "execute", connection.execute)
        migration.upgrade()
        row = connection.execute(
            text("SELECT finding_id, redacted_evidence, message FROM app.findings")
        ).one()

    assert row.finding_id == "OG:stable"
    assert "opaque-canary-12345" not in row.redacted_evidence
    assert row.message == "Static message"
