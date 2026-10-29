from __future__ import annotations

from security_review.domain.models import Confidence, Finding, Severity
from security_review.intelligence.fakes import FakeDocumentRetriever
from security_review.intelligence.models import DocumentChunk
from security_review.orchestrator.scan_graph import ScanGraphServices, build_scan_graph

COMMIT = "a" * 40


def test_precomputed_history_finding_keeps_provenance_after_rag_enrichment() -> None:
    finding = Finding(
        id=f"gitleaks:{COMMIT}:config.py:2",
        rule_id="gitleaks:generic-api-key",
        category="secret",
        severity=Severity.HIGH,
        file_path="config.py",
        line_start=2,
        git_commit=COMMIT,
        message="A secret-like value was found in Git history.",
        redacted_evidence="[REDACTED: secret value omitted]",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-798",),
        remediation="Rotate the credential.",
        engine="gitleaks",
    )
    retriever = FakeDocumentRetriever(
        results=(
            DocumentChunk(
                id="guide:1",
                text="Rotate and replace leaked credentials.",
                title="Secret response",
                source_url="https://example.test/guide",
                score=0.9,
            ),
        )
    )

    result = build_scan_graph(ScanGraphServices(retriever=retriever)).invoke(
        {"findings": (finding,)}
    )

    enriched = result["findings"][0]
    assert enriched.git_commit == COMMIT
    assert result["report"].findings[0].git_commit == COMMIT
    assert enriched.references
