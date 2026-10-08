"""A ready real Qdrant connection can fail at an isolated search boundary."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from qdrant_client import QdrantClient

from security_review.api.app import create_app
from security_review.application import scan_path
from security_review.config import Settings
from security_review.intelligence.fakes import FakeChatModel, FakeEmbeddingModel
from security_review.intelligence.qdrant_retriever import bootstrap_collection
from security_review.scanner.files import ScanLimits

pytestmark = pytest.mark.integration


def test_live_qdrant_search_failure_preserves_deterministic_findings(tmp_path: Path) -> None:
    database_url = os.getenv(
        "SECRAGRAPH_TEST_DATABASE_URL",
        "postgresql+psycopg://secragraph@localhost:55432/secragraph_test",
    )
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    source = tmp_path / "sample.py"
    source.write_text("eval(user_input)\n", encoding="utf-8")
    baseline = scan_path(source, ScanLimits())
    assert baseline.findings

    qdrant_url = os.getenv("SECRAGRAPH_TEST_QDRANT_URL", "http://127.0.0.1:56333")
    qdrant = QdrantClient(url=qdrant_url, timeout=5)
    collection = f"secragraph-partial-{uuid4().hex}"
    created = False
    try:
        bootstrap_collection(qdrant, collection, 3)
        created = True
        app = create_app(
            Settings(
                database_url=database_url,
                intelligence_database_url=database_url,
                qdrant_url=qdrant_url,
                qdrant_collection=collection,
                qdrant_vector_dimension=3,
                openai_api_key=None,
            ),
            chat_model=FakeChatModel(()),
            embeddings=FakeEmbeddingModel(dimension=3),
            qdrant_client=qdrant,
        )
        with TestClient(app) as client:
            readiness = client.get("/health/ready")
            assert readiness.status_code == 200
            with patch.object(qdrant, "query_points", side_effect=OSError("isolated outage")):
                response = client.post(
                    "/v1/scans/file",
                    files={"file": ("sample.py", source.read_bytes(), "text/x-python")},
                )

        assert response.status_code == 200
        report = response.json()
        assert report["status"] == "completed_with_warnings"
        assert "enrichment_qdrant_unavailable" in report["warnings"]
        assert [item["id"] for item in report["findings"]] == [
            str(finding.id) for finding in baseline.findings
        ]
    finally:
        if created:
            qdrant.delete_collection(collection)
        qdrant.close()
