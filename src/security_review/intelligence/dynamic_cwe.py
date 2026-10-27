"""Bounded per-ID MITRE evidence acquisition; untrusted content stays data."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, TimeoutError, wait
from dataclasses import dataclass
from pathlib import Path
from threading import RLock, Thread
from time import monotonic
from typing import Any, Protocol, cast
from uuid import UUID

import httpx

from security_review.domain.models import SourceReference
from security_review.intelligence.case_corpus import (
    _API_ROOT,
    _ID_PATTERN,
    CorpusAcquisitionError,
    _atomic_json,
    _load_cached_snapshot,
    _make_client,
    _publish_snapshot,
    _read_api_json,
    _read_bounded_json,
    _version,
    _weakness_document,
)
from security_review.intelligence.ingestion import (
    DocumentChunkInput,
    DocumentIngestionError,
    _has_link_like_component,
    chunk_documents,
)
from security_review.intelligence.manifest import (
    ManifestError,
    VerifiedCorpus,
    load_verified_corpus,
)
from security_review.ports import IntelligenceError

RUNTIME_CWE_CORPUS_ID = "secragraph-runtime-cwe-v1"
MAX_SCAN_CWE_IDS = 64
MAX_RUNTIME_DOCUMENTS = 1_024
MAX_RUNTIME_CACHE_BYTES = 16_000_000
MAX_RUNTIME_RESPONSE_BYTES = 8_000_000
MAX_RUNTIME_SECONDS = 12.0
_MAX_IN_FLIGHT = 4
_CACHE_NAME = re.compile(r"cwe-[1-9][0-9]{0,5}\Z")


def _close_client_after_futures(client: httpx.Client, futures: Sequence[Future[Any]]) -> None:
    wait(futures)
    client.close()


class CweDocumentIndexer(Protocol):
    """Only the additive per-document write operation is required."""

    def replace_documents(
        self, chunks: Sequence[DocumentChunkInput], *, batch_size: int = 64
    ) -> int: ...


class _CorpusPreview(Protocol):
    stale_document_ids: Sequence[UUID]


@dataclass(frozen=True, slots=True)
class CweEvidenceResult:
    references_by_id: Mapping[str, SourceReference]
    warnings: tuple[str, ...] = ()


class CweEvidenceProvider(Protocol):
    def ensure(
        self, cwe_ids: Sequence[str], *, deadline: float | None = None
    ) -> CweEvidenceResult: ...


class LiveCweEvidenceProvider:
    """Fetch verified official records on cache miss and optionally index them.

    The provider owns one in-process lock: competing requests cannot publish a
    partially written snapshot or index the same document twice. Normal warm
    calls read a bounded verified cache without any MITRE request.
    """

    def __init__(
        self,
        cache_root: Path,
        *,
        indexer: CweDocumentIndexer | None = None,
        offline: bool = False,
        http_client: httpx.Client | None = None,
        clock: Callable[[], float] = monotonic,
        max_cache_bytes: int = MAX_RUNTIME_CACHE_BYTES,
    ) -> None:
        if (
            type(max_cache_bytes) is not int
            or not 1_024 <= max_cache_bytes <= MAX_RUNTIME_CACHE_BYTES
        ):
            raise ValueError("max_cache_bytes is out of range")
        self._cache_root = cache_root
        self._indexer = indexer
        self._offline = offline
        self._http_client = http_client
        self._clock = clock
        self._max_cache_bytes = max_cache_bytes
        self._lock = RLock()
        self._indexed_documents: set[UUID] = set()
        self._known_index_documents: set[UUID] | None = None
        self._index_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cwe-index")
        self._index_pending: dict[UUID, Future[int]] = {}
        self._preview_future: Future[object] | None = None
        self._refresh_required: set[UUID] = set()

    def ensure(self, cwe_ids: Sequence[str], *, deadline: float | None = None) -> CweEvidenceResult:
        now = self._clock()
        end = (
            min(deadline, now + MAX_RUNTIME_SECONDS)
            if deadline is not None
            else now + MAX_RUNTIME_SECONDS
        )
        valid: list[str] = []
        warnings: list[str] = []
        for value in cwe_ids:
            if not isinstance(value, str) or _ID_PATTERN.fullmatch(value) is None:
                warnings.append("cwe_evidence_partial")
                continue
            if value not in valid:
                valid.append(value)
        valid.sort(key=lambda item: int(item[4:]))
        if len(valid) > MAX_SCAN_CWE_IDS:
            valid = valid[:MAX_SCAN_CWE_IDS]
            warnings.append("cwe_evidence_limit_reached")
        if not valid:
            return CweEvidenceResult({}, tuple(dict.fromkeys(warnings)))
        if not self._lock.acquire(timeout=max(0.0, end - self._clock())):
            warnings.append("cwe_evidence_partial")
            return CweEvidenceResult({}, tuple(dict.fromkeys(warnings)))
        try:
            return self._ensure_locked(tuple(valid), end, warnings)
        finally:
            self._lock.release()

    def _ensure_locked(
        self, ids: tuple[str, ...], deadline: float, warnings: list[str]
    ) -> CweEvidenceResult:
        if _has_link_like_component(self._cache_root):
            return CweEvidenceResult({}, (*dict.fromkeys(warnings), "cwe_evidence_unavailable"))
        try:
            self._cache_root.mkdir(parents=True, exist_ok=True)
            if _has_link_like_component(self._cache_root):
                raise OSError("unsafe cache path")
        except OSError:
            return CweEvidenceResult({}, (*dict.fromkeys(warnings), "cwe_evidence_unavailable"))

        verified: dict[str, VerifiedCorpus] = {}
        freshly_acquired: set[str] = set()
        missing: list[str] = []
        for cwe_id in ids:
            if self._clock() >= deadline:
                warnings.append("cwe_evidence_partial")
                break
            cached = _load_cached_snapshot(
                self._cache_root / cwe_id.lower(),
                (cwe_id,),
                corpus_id=RUNTIME_CWE_CORPUS_ID,
            )
            if cached is None:
                missing.append(cwe_id)
                continue
            try:
                verified[cwe_id] = load_verified_corpus(cached.root, cached.manifest_path)
            except (ManifestError, OSError, ValueError):
                missing.append(cwe_id)
        if missing and not self._offline and self._clock() < deadline:
            self._acquire_missing(missing, verified, freshly_acquired, warnings, deadline)
        elif missing:
            warnings.append("cwe_evidence_partial")

        references: dict[str, SourceReference] = {}
        for cwe_id in ids:
            corpus = verified.get(cwe_id)
            if corpus is None:
                continue
            if (
                corpus.corpus_id != RUNTIME_CWE_CORPUS_ID
                or len(corpus.entries) != 1
                or len(corpus.documents) != 1
            ):
                warnings.append("cwe_evidence_partial")
                continue
            entry = corpus.entries[0]
            document = corpus.documents[0]
            references[cwe_id] = SourceReference(
                id=f"mitre:{cwe_id}",
                title=document.title,
                source_url=entry.source_url,
            )
            if self._indexer is not None:
                self._index(
                    cwe_id,
                    corpus,
                    warnings,
                    deadline,
                    force=cwe_id in freshly_acquired,
                )
        try:
            self._evict_old_cache()
        except OSError:
            warnings.append("cwe_evidence_partial")
        return CweEvidenceResult(references, tuple(dict.fromkeys(warnings)))

    def _acquire_missing(
        self,
        missing: list[str],
        verified: dict[str, VerifiedCorpus],
        freshly_acquired: set[str],
        warnings: list[str],
        deadline: float,
    ) -> None:
        owner = self._http_client is None
        client = self._http_client or _make_client()
        executor = ThreadPoolExecutor(max_workers=_MAX_IN_FLIGHT)
        all_futures: list[Future[Any]] = []
        pending: dict[Future[tuple[bytes, str, int]], tuple[str, int]] = {}
        try:
            try:
                version_future = executor.submit(
                    _version, client, deadline=deadline, clock=self._clock
                )
                all_futures.append(version_future)
                revision, source_date, version_bytes = version_future.result(
                    timeout=max(0.0, deadline - self._clock())
                )
            except (CorpusAcquisitionError, TimeoutError, httpx.HTTPError):
                warnings.append("cwe_evidence_partial")
                return
            remaining_bytes = MAX_RUNTIME_RESPONSE_BYTES - version_bytes
            if remaining_bytes <= 0:
                warnings.append("cwe_evidence_partial")
                return

            def fetch(cwe_id: str, allowance: int) -> tuple[bytes, str, int]:
                payload, digest, size = _read_api_json(
                    client,
                    f"{_API_ROOT}/weakness/{cwe_id[4:]}",
                    remaining_bytes=allowance,
                    deadline=deadline,
                    clock=self._clock,
                )
                document = _weakness_document(payload, cwe_id, revision, source_date)
                if len(document) > 100_000:
                    raise CorpusAcquisitionError("generated_document_too_large")
                return document, digest, size

            fetched: dict[str, tuple[bytes, str, int]] = {}
            consumed = 0
            reserved = 0
            next_index = 0
            while self._clock() < deadline:
                while next_index < len(missing) and len(pending) < _MAX_IN_FLIGHT:
                    allowance = min(256_000, remaining_bytes - consumed - reserved)
                    if allowance <= 0:
                        break
                    cwe_id = missing[next_index]
                    next_index += 1
                    future = executor.submit(fetch, cwe_id, allowance)
                    all_futures.append(future)
                    pending[future] = (cwe_id, allowance)
                    reserved += allowance
                if not pending:
                    break
                completed, _ = wait(
                    pending,
                    timeout=max(0.0, deadline - self._clock()),
                    return_when=FIRST_COMPLETED,
                )
                if not completed:
                    warnings.append("cwe_evidence_partial")
                    break
                for future in completed:
                    cwe_id, allowance = pending.pop(future)
                    reserved -= allowance
                    try:
                        record = future.result()
                        fetched[cwe_id] = record
                        consumed += record[2]
                    except (CorpusAcquisitionError, httpx.HTTPError, ValueError):
                        # Reserve the maximum possible transfer on failure.
                        consumed += allowance
                        warnings.append("cwe_evidence_partial")
            if pending or next_index < len(missing):
                warnings.append("cwe_evidence_partial")
            for cwe_id in missing:
                cached_record = fetched.get(cwe_id)
                if cached_record is None or self._clock() >= deadline:
                    warnings.append("cwe_evidence_partial")
                    continue
                document, digest, _size = cached_record
                directory = self._cache_root / cwe_id.lower()
                if _has_link_like_component(directory):
                    warnings.append("cwe_evidence_partial")
                    continue
                try:
                    directory.mkdir(parents=True, exist_ok=True)
                    snapshot = _publish_snapshot(
                        directory,
                        (cwe_id,),
                        revision,
                        source_date,
                        {cwe_id: document},
                        {cwe_id: digest},
                        corpus_id=RUNTIME_CWE_CORPUS_ID,
                    )
                    verified[cwe_id] = load_verified_corpus(snapshot.root, snapshot.manifest_path)
                    freshly_acquired.add(cwe_id)
                except (CorpusAcquisitionError, ManifestError, OSError, ValueError):
                    warnings.append("cwe_evidence_partial")
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            if owner:
                if any(not future.done() for future in all_futures):
                    Thread(
                        target=_close_client_after_futures,
                        args=(client, tuple(all_futures)),
                        daemon=True,
                    ).start()
                else:
                    client.close()

    def _index(
        self,
        cwe_id: str,
        corpus: VerifiedCorpus,
        warnings: list[str],
        deadline: float,
        *,
        force: bool,
    ) -> None:
        indexer = self._indexer
        if indexer is None:
            return
        try:
            self._finish_completed_indexes(warnings)
            chunks = chunk_documents(corpus.documents, 350, 50, max_total_chunks=256)
            document_id = chunks[0].document_id
            marker_path = self._cache_root / cwe_id.lower() / "indexed.json"
            expected_marker = {
                "schema_version": 1,
                "corpus_id": RUNTIME_CWE_CORPUS_ID,
                "document_sha256": corpus.entries[0].sha256,
            }
            try:
                marker = _read_bounded_json(marker_path)
            except CorpusAcquisitionError:
                marker = None
            if marker != expected_marker:
                force = True
            if force:
                self._refresh_required.add(document_id)
            force = document_id in self._refresh_required
            if self._clock() >= deadline:
                warnings.append("cwe_evidence_partial")
                return
            if document_id in self._indexed_documents and not force:
                return
            if self._known_index_documents is None:
                preview_method = getattr(indexer, "preview_corpus_sync", None)
                if callable(preview_method):
                    if self._preview_future is None:
                        self._preview_future = self._index_executor.submit(
                            preview_method, RUNTIME_CWE_CORPUS_ID, set()
                        )
                    try:
                        preview = cast(
                            _CorpusPreview,
                            self._preview_future.result(timeout=max(0.0, deadline - self._clock())),
                        )
                    except TimeoutError:
                        warnings.append("cwe_evidence_partial")
                        return
                    except Exception:
                        self._preview_future = None
                        warnings.append("cwe_evidence_partial")
                        return
                    self._known_index_documents = set(preview.stale_document_ids)
                    self._preview_future = None
                else:
                    self._known_index_documents = set()
            if document_id in self._known_index_documents and not force:
                self._indexed_documents.add(document_id)
                return
            if self._clock() >= deadline:
                warnings.append("cwe_evidence_partial")
                return
            future = self._index_pending.get(document_id)
            if future is not None and force:
                try:
                    future.result(timeout=max(0.0, deadline - self._clock()))
                except TimeoutError:
                    warnings.append("cwe_evidence_partial")
                    return
                except Exception:
                    warnings.append("cwe_evidence_partial")
                self._index_pending.pop(document_id, None)
                future = None
            if future is None:
                if document_id not in self._known_index_documents and (
                    len(self._known_index_documents) + len(self._index_pending)
                    >= MAX_RUNTIME_DOCUMENTS
                ):
                    warnings.append("cwe_evidence_limit_reached")
                    return
                if len(self._index_pending) >= _MAX_IN_FLIGHT:
                    warnings.append("cwe_evidence_partial")
                    return
                future = self._index_executor.submit(indexer.replace_documents, chunks)
                self._index_pending[document_id] = future
            try:
                future.result(timeout=max(0.0, deadline - self._clock()))
            except TimeoutError:
                warnings.append("cwe_evidence_partial")
                return
            except Exception:
                self._index_pending.pop(document_id, None)
                warnings.append("cwe_evidence_partial")
                return
            self._index_pending.pop(document_id, None)
            self._indexed_documents.add(document_id)
            self._known_index_documents.add(document_id)
            self._refresh_required.discard(document_id)
            try:
                _atomic_json(marker_path, expected_marker)
            except (CorpusAcquisitionError, OSError):
                warnings.append("cwe_evidence_partial")
        except (
            DocumentIngestionError,
            IntelligenceError,
            ValueError,
            RuntimeError,
            AttributeError,
            OSError,
        ):
            warnings.append("cwe_evidence_partial")

    def _finish_completed_indexes(self, warnings: list[str]) -> None:
        for document_id, future in tuple(self._index_pending.items()):
            if not future.done():
                continue
            self._index_pending.pop(document_id)
            try:
                future.result()
            except Exception:
                warnings.append("cwe_evidence_partial")
                continue
            self._indexed_documents.add(document_id)
            if self._known_index_documents is not None:
                self._known_index_documents.add(document_id)

    def _evict_old_cache(self) -> None:
        root = self._cache_root.resolve(strict=True)
        directories = [
            child
            for child in root.iterdir()
            if _CACHE_NAME.fullmatch(child.name)
            and child.is_dir()
            and not _has_link_like_component(child)
        ]
        sizes: dict[Path, int] = {}
        for directory in directories:
            sizes[directory] = sum(
                path.stat().st_size
                for path in directory.rglob("*")
                if path.is_file() and not _has_link_like_component(path)
            )
        total = sum(sizes.values())
        if total <= self._max_cache_bytes:
            return
        for directory in sorted(
            directories,
            key=lambda item: (
                (item / "current.json").stat().st_mtime if (item / "current.json").exists() else 0
            ),
        ):
            if total <= self._max_cache_bytes:
                break
            resolved = directory.resolve(strict=True)
            if not resolved.is_relative_to(root) or _has_link_like_component(directory):
                continue
            shutil.rmtree(directory)
            total -= sizes[directory]
