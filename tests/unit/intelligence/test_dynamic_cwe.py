"""Actual findings and question topics acquire independent official CWE records."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest

from security_review.evaluation.scanner_models import load_scanner_cases
from security_review.intelligence import case_corpus
from security_review.intelligence.dynamic_cwe import (
    RUNTIME_CWE_CORPUS_ID,
    LiveCweEvidenceProvider,
)
from security_review.intelligence.ingestion import DocumentChunkInput
from security_review.intelligence.manifest import load_verified_corpus

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def cache_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("dc")


def _response(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=httpx.ByteStream(json.dumps(payload).encode("utf-8")),
    )


def _client(urls: list[str], *, wrong_id: bool = False, name: str | None = None) -> httpx.Client:
    def dispatch(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        assert request.url.scheme == "https"
        assert request.url.host == "cwe-api.mitre.org"
        if request.url.path == "/api/v1/cwe/version":
            return _response({"ContentVersion": "4.20", "ContentDate": "2026-07-16"})
        number = request.url.path.rsplit("/", 1)[-1]
        assert request.url.path == f"/api/v1/cwe/weakness/{number}"
        return _response(
            {
                "Weaknesses": [
                    {
                        "ID": "999" if wrong_id else number,
                        "Name": name or f"Official weakness {number}",
                        "Description": f"Official description for weakness {number}.",
                        "PotentialMitigations": [],
                    }
                ]
            }
        )

    return httpx.Client(transport=httpx.MockTransport(dispatch), follow_redirects=False)


def test_new_cwe_is_verified_and_cached_separately(cache_dir: Path) -> None:
    urls: list[str] = []
    with _client(urls) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client)
        result = provider.ensure(["CWE-22", "CWE-22"])

    assert result.warnings == ()
    assert set(result.references_by_id) == {"CWE-22"}
    assert result.references_by_id["CWE-22"].source_url == (
        "https://cwe-api.mitre.org/api/v1/cwe/weakness/22"
    )
    assert urls == [
        "https://cwe-api.mitre.org/api/v1/cwe/version",
        "https://cwe-api.mitre.org/api/v1/cwe/weakness/22",
    ]
    snapshots = list((cache_dir / "cwe-22" / "snapshots").glob("*/manifest.json"))
    assert len(snapshots) == 1
    corpus = load_verified_corpus(snapshots[0].parent, snapshots[0])
    assert corpus.corpus_id == RUNTIME_CWE_CORPUS_ID
    assert "Official description for weakness 22" in corpus.documents[0].text


def test_warm_and_offline_cache_never_call_network(cache_dir: Path) -> None:
    with _client([]) as client:
        assert (
            LiveCweEvidenceProvider(cache_dir, http_client=client)
            .ensure(["CWE-22"])
            .references_by_id
        )

    urls: list[str] = []
    with _client(urls) as client:
        cached = LiveCweEvidenceProvider(cache_dir, http_client=client, offline=True).ensure(
            ["CWE-22"]
        )
    assert cached.references_by_id["CWE-22"].title.startswith("CWE-22")
    assert cached.warnings == ()
    assert urls == []


def test_corrupt_cache_is_not_trusted_offline(cache_dir: Path) -> None:
    with _client([]) as client:
        LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])
    document = next((cache_dir / "cwe-22" / "snapshots").glob("*/cwe-22.md"))
    document.write_text("tampered", encoding="utf-8")

    result = LiveCweEvidenceProvider(cache_dir, offline=True).ensure(["CWE-22"])
    assert result.references_by_id == {}
    assert "cwe_evidence_partial" in result.warnings


def test_mismatched_official_id_is_rejected(cache_dir: Path) -> None:
    with _client([], wrong_id=True) as client:
        result = LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])
    assert result.references_by_id == {}
    assert "cwe_evidence_partial" in result.warnings


@pytest.mark.parametrize("name", ["A" * 300, "*" * 300])
def test_long_official_name_stays_within_manifest_title_limit(cache_dir: Path, name: str) -> None:
    with _client([], name=name) as client:
        result = LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])
    assert result.warnings == ()
    assert len(result.references_by_id["CWE-22"].title) <= 300


def test_invalid_id_and_expired_deadline_make_no_network_calls(cache_dir: Path) -> None:
    urls: list[str] = []
    with _client(urls) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client, clock=lambda: 50.0)
        invalid = provider.ensure(["CWE-0", "CWE-22/../../secret"])
        expired = provider.ensure(["CWE-22"], deadline=49.0)
    assert invalid.references_by_id == {}
    assert "cwe_evidence_partial" in invalid.warnings
    assert expired.references_by_id == {}
    assert "cwe_evidence_partial" in expired.warnings
    assert urls == []


class RecordingIndexer:
    def __init__(self) -> None:
        self.documents: dict[str, set[str]] = {}
        self.calls = 0

    def replace_documents(
        self, chunks: Sequence[DocumentChunkInput], *, batch_size: int = 64
    ) -> int:
        self.calls += 1
        grouped: dict[str, set[str]] = {}
        for chunk in chunks:
            assert chunk.corpus_id == RUNTIME_CWE_CORPUS_ID
            grouped.setdefault(str(chunk.document_id), set()).add(str(chunk.id))
        self.documents.update(grouped)
        return sum(map(len, grouped.values()))


def test_new_runtime_cwe_indexing_preserves_sibling_documents(cache_dir: Path) -> None:
    indexer = RecordingIndexer()
    with _client([]) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client, indexer=indexer)
        first = provider.ensure(["CWE-22"])
        second = provider.ensure(["CWE-601"])
        again = provider.ensure(["CWE-22"])
    assert not first.warnings and not second.warnings and not again.warnings
    assert len(indexer.documents) == 2
    assert indexer.calls == 2


def test_fresh_official_revision_replaces_same_qdrant_document_id(cache_dir: Path) -> None:
    class PreviewIndexer(RecordingIndexer):
        def __init__(self) -> None:
            super().__init__()
            self.indexed_texts: list[str] = []

        def preview_corpus_sync(
            self, corpus_id: str, desired_document_ids: set[object]
        ) -> SimpleNamespace:
            assert corpus_id == RUNTIME_CWE_CORPUS_ID
            assert not desired_document_ids
            return SimpleNamespace(
                stale_document_ids=tuple(UUID(value) for value in self.documents)
            )

        def replace_documents(
            self, chunks: Sequence[DocumentChunkInput], *, batch_size: int = 64
        ) -> int:
            self.indexed_texts.append("\n".join(f"{chunk.title}\n{chunk.text}" for chunk in chunks))
            return super().replace_documents(chunks, batch_size=batch_size)

    indexer = PreviewIndexer()
    with _client([]) as client:
        first = LiveCweEvidenceProvider(
            cache_dir / "first", http_client=client, indexer=indexer
        ).ensure(["CWE-22"])
    with _client([], name="Updated official weakness 22") as client:
        second = LiveCweEvidenceProvider(
            cache_dir / "second", http_client=client, indexer=indexer
        ).ensure(["CWE-22"])

    assert not first.warnings and not second.warnings
    assert indexer.calls == 2
    assert "Updated official weakness 22" in indexer.indexed_texts[-1]


def test_failed_index_refresh_is_retried_from_verified_cache(cache_dir: Path) -> None:
    class FlakyIndexer(RecordingIndexer):
        fail = False

        def preview_corpus_sync(
            self, corpus_id: str, desired_document_ids: set[object]
        ) -> SimpleNamespace:
            return SimpleNamespace(
                stale_document_ids=tuple(UUID(value) for value in self.documents)
            )

        def replace_documents(
            self, chunks: Sequence[DocumentChunkInput], *, batch_size: int = 64
        ) -> int:
            if self.fail:
                raise RuntimeError("injected index failure")
            self.last_title = chunks[0].title
            return super().replace_documents(chunks, batch_size=batch_size)

    indexer = FlakyIndexer()
    with _client([]) as client:
        LiveCweEvidenceProvider(cache_dir / "old", http_client=client, indexer=indexer).ensure(
            ["CWE-22"]
        )
    indexer.fail = True
    with _client([], name="Updated official weakness 22") as client:
        failed = LiveCweEvidenceProvider(
            cache_dir / "new", http_client=client, indexer=indexer
        ).ensure(["CWE-22"])
    indexer.fail = False
    recovered = LiveCweEvidenceProvider(cache_dir / "new", offline=True, indexer=indexer).ensure(
        ["CWE-22"]
    )

    assert "cwe_evidence_partial" in failed.warnings
    assert recovered.warnings == ()
    assert indexer.calls == 2
    assert "Updated official weakness 22" in indexer.last_title


def test_scan_size_cap_is_independent_of_benchmark_case_count(cache_dir: Path) -> None:
    ids = [f"CWE-{number}" for number in range(1, 66)]
    result = LiveCweEvidenceProvider(cache_dir, offline=True).ensure(ids)
    assert result.references_by_id == {}
    assert "cwe_evidence_limit_reached" in result.warnings


def test_runtime_fetches_more_than_32_distinct_small_cwe_records(cache_dir: Path) -> None:
    ids = [f"CWE-{number}" for number in range(1000, 1033)]
    urls: list[str] = []
    with _client(urls) as client:
        result = LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(ids)

    assert set(result.references_by_id) == set(ids)
    assert result.warnings == ()
    assert len(urls) == len(ids) + 1  # one version request, then each selected CWE


def test_current_rules_are_preloaded_even_without_positive_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extra_rule = replace(case_corpus.DEFAULT_RULES[0], rule_id="NEW001", cwe_ids=("CWE-22",))
    monkeypatch.setattr(case_corpus, "DEFAULT_RULES", (*case_corpus.DEFAULT_RULES, extra_rule))

    selected = case_corpus._select_case_cwes(REPO_ROOT)

    assert "CWE-22" in selected.cwe_ids
    assert len(selected.scanner_cases) == len(
        load_scanner_cases(REPO_ROOT / "data/evaluation/scanner_cases.json")
    )
    assert len(selected.rag_cases) == 4
    assert all("CWE-22" not in ids for ids in selected.scanner_cases.values())


def test_startup_selection_accepts_more_than_32_current_rule_cwes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    additional_rules = tuple(
        replace(
            case_corpus.DEFAULT_RULES[0],
            rule_id=f"EXTRA-{number}",
            cwe_ids=(f"CWE-{number}",),
        )
        for number in range(1000, 1040)
    )
    monkeypatch.setattr(
        case_corpus,
        "DEFAULT_RULES",
        (*case_corpus.DEFAULT_RULES, *additional_rules),
    )

    selected = case_corpus._select_case_cwes(REPO_ROOT)

    assert set(f"CWE-{number}" for number in range(1000, 1040)).issubset(selected.cwe_ids)
    assert len(selected.cwe_ids) == 48
    assert len(selected.scanner_cases) == len(
        load_scanner_cases(REPO_ROOT / "data/evaluation/scanner_cases.json")
    )
    assert len(selected.rag_cases) == 4


def test_slow_official_request_does_not_hold_call_past_deadline(cache_dir: Path) -> None:
    urls: list[str] = []

    def dispatch(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/weakness/22"):
            time.sleep(0.65)
        return _client_response(request, urls)

    with httpx.Client(transport=httpx.MockTransport(dispatch)) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client)
        started = time.monotonic()
        result = provider.ensure(["CWE-22"], deadline=started + 0.1)
        duration = time.monotonic() - started

    assert duration < 0.45
    assert result.references_by_id == {}
    assert "cwe_evidence_partial" in result.warnings


def test_slow_version_request_does_not_hold_call_past_deadline(cache_dir: Path) -> None:
    urls: list[str] = []

    def dispatch(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/version"):
            time.sleep(0.65)
        return _client_response(request, urls)

    with httpx.Client(transport=httpx.MockTransport(dispatch)) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client)
        started = time.monotonic()
        result = provider.ensure(["CWE-22"], deadline=started + 0.1)
        duration = time.monotonic() - started

    assert duration < 0.45
    assert result.references_by_id == {}
    assert "cwe_evidence_partial" in result.warnings


def test_concurrent_request_cannot_wait_past_its_deadline(cache_dir: Path) -> None:
    urls: list[str] = []
    ready = Event()
    release = Event()
    with _client(urls) as client:
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client)

        def hold_provider() -> None:
            with provider._lock:
                ready.set()
                release.wait(timeout=2.0)

        holder = Thread(target=hold_provider)
        holder.start()
        assert ready.wait(timeout=1.0)
        try:
            started = time.monotonic()
            result = provider.ensure(["CWE-22"], deadline=started + 0.1)
            duration = time.monotonic() - started
        finally:
            release.set()
            holder.join(timeout=2.0)

    assert duration < 0.45
    assert result.references_by_id == {}
    assert "cwe_evidence_partial" in result.warnings
    assert urls == []


def test_slow_index_does_not_hold_call_past_deadline(cache_dir: Path) -> None:
    with _client([]) as client:
        LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])

    started_index = Event()

    class SlowIndexer(RecordingIndexer):
        def replace_documents(
            self, chunks: Sequence[DocumentChunkInput], *, batch_size: int = 64
        ) -> int:
            started_index.set()
            time.sleep(2.0)
            return super().replace_documents(chunks, batch_size=batch_size)

    indexer = SlowIndexer()
    provider = LiveCweEvidenceProvider(cache_dir, offline=True, indexer=indexer)
    started = time.monotonic()
    result = provider.ensure(["CWE-22"], deadline=started + 1.0)
    duration = time.monotonic() - started

    assert started_index.is_set()
    assert duration < 1.5
    assert "CWE-22" in result.references_by_id
    assert "cwe_evidence_partial" in result.warnings


def test_cache_eviction_keeps_dedicated_root_below_limit(cache_dir: Path) -> None:
    with _client([]) as client:
        LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])
        first_size = sum(path.stat().st_size for path in cache_dir.rglob("*") if path.is_file())
        cap = max(1_024, first_size + 100)
        provider = LiveCweEvidenceProvider(cache_dir, http_client=client, max_cache_bytes=cap)
        result = provider.ensure(["CWE-601"])

    remaining_size = sum(path.stat().st_size for path in cache_dir.rglob("*") if path.is_file())
    assert result.references_by_id["CWE-601"].source_url.endswith("/weakness/601")
    assert remaining_size <= cap
    assert not (cache_dir / "cwe-22").exists()


def test_runtime_document_limit_preserves_verified_reference(cache_dir: Path) -> None:
    with _client([]) as client:
        LiveCweEvidenceProvider(cache_dir, http_client=client).ensure(["CWE-22"])

    class FullIndexer(RecordingIndexer):
        def preview_corpus_sync(
            self, corpus_id: str, desired_document_ids: set[object]
        ) -> SimpleNamespace:
            assert corpus_id == RUNTIME_CWE_CORPUS_ID
            assert not desired_document_ids
            return SimpleNamespace(stale_document_ids=tuple(uuid4() for _ in range(1024)))

    indexer = FullIndexer()
    result = LiveCweEvidenceProvider(cache_dir, offline=True, indexer=indexer).ensure(["CWE-22"])

    assert "CWE-22" in result.references_by_id
    assert "cwe_evidence_limit_reached" in result.warnings
    assert indexer.calls == 0


def _client_response(request: httpx.Request, urls: list[str]) -> httpx.Response:
    urls.append(str(request.url))
    if request.url.path == "/api/v1/cwe/version":
        return _response({"ContentVersion": "4.20", "ContentDate": "2026-07-16"})
    number = request.url.path.rsplit("/", 1)[-1]
    return _response(
        {
            "Weaknesses": [
                {
                    "ID": number,
                    "Name": f"Official weakness {number}",
                    "Description": f"Official description for weakness {number}.",
                    "PotentialMitigations": [],
                }
            ]
        }
    )
