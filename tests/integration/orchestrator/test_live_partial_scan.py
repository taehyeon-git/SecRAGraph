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

from security_review import application
from security_review.api.app import create_app
from security_review.application import scan_path
from security_review.config import Settings
from security_review.domain.models import Confidence, Finding, Severity
from security_review.intelligence.fakes import FakeChatModel, FakeEmbeddingModel
from security_review.intelligence.qdrant_retriever import bootstrap_collection
from security_review.scanner.external_common import ExternalExecution, ExternalScanResult
from security_review.scanner.files import ScanLimits

pytestmark = pytest.mark.integration


class _StaticSastAdapter:
    """Keep this Qdrant failure test independent of installed scanner binaries."""

    def __init__(self) -> None:
        self.calls = 0

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        assert timeout > 0
        assert (root / "sample.py").is_file()
        self.calls += 1
        return ExternalScanResult(
            findings=(
                Finding(
                    id="OG/integration-eval:sample.py:1",
                    rule_id="OG/integration-eval",
                    category="sast",
                    severity=Severity.HIGH,
                    file_path="sample.py",
                    line_start=1,
                    message="Synthetic eval call",
                    redacted_evidence="[source omitted]",
                    confidence=Confidence.MEDIUM,
                    remediation="Review untrusted input before evaluation.",
                    engine="opengrep",
                ),
            ),
            execution=ExternalExecution(
                scanner="opengrep",
                version="test",
                status="completed",
                eligible_files=("sample.py",),
                inspected_files=("sample.py",),
                checks=("OG/integration-eval",),
            ),
        )


def test_live_qdrant_search_failure_preserves_deterministic_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = _StaticSastAdapter()
    monkeypatch.setattr(application, "OpengrepAdapter", lambda: scanner)
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
            username = f"partial-{uuid4().hex[:12]}"
            password = "integration-only-password"
            app.state.membership_service.register(username, password)
            login = client.post("/v1/auth/login", json={"username": username, "password": password})
            assert login.status_code == 200
            headers = {"Authorization": f"Session {login.json()['token']}"}
            with patch.object(qdrant, "query_points", side_effect=OSError("isolated outage")):
                response = client.post(
                    "/v1/scans/file",
                    files={"file": ("sample.py", source.read_bytes(), "text/x-python")},
                    headers=headers,
                )

        assert response.status_code == 200
        report = response.json()
        assert report["status"] == "completed_with_warnings"
        assert "enrichment_qdrant_unavailable" in report["warnings"]
        assert [item["id"] for item in report["findings"]] == [
            str(finding.id) for finding in baseline.findings
        ]
        assert scanner.calls >= 2
    finally:
        if created:
            qdrant.delete_collection(collection)
        qdrant.close()
