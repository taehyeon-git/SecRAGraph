"""Qdrant-backed ingestion and retrieval for untrusted security evidence."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from pydantic import ValidationError
from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.exceptions import ApiException

from security_review.intelligence.ingestion import MAX_CHUNK_BYTES, DocumentChunkInput
from security_review.intelligence.models import DocumentChunk
from security_review.ports import (
    EmbeddingModel,
    IntelligenceConfigurationError,
    IntelligenceUnavailableError,
)

_PROVIDER_ERRORS = (ApiException, httpx.HTTPError, OSError, TimeoutError)
MAX_RETRIEVED_TEXT_BYTES = 128_000
_REPLACEMENT_PAGE_SIZE = 256
_MAX_SNAPSHOT_POINTS_PER_DOCUMENT = 20_000
_MAX_SNAPSHOT_POINTS_TOTAL = 20_000
_MAX_SNAPSHOT_PAGES = 80
_SEARCH_PAYLOAD_FIELDS = ["id", "text", "title", "source_url", "page", "section"]
_PAYLOAD_INDEXES = (
    ("document_id", models.PayloadSchemaType.KEYWORD),
    ("source_path", models.PayloadSchemaType.KEYWORD),
    ("source_url", models.PayloadSchemaType.KEYWORD),
    ("page", models.PayloadSchemaType.INTEGER),
    ("section", models.PayloadSchemaType.KEYWORD),
    ("generation_id", models.PayloadSchemaType.KEYWORD),
)


class CollectionConfigurationError(IntelligenceConfigurationError):
    """A Qdrant collection exists with an incompatible vector contract."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, capability="qdrant")


def bootstrap_collection(client: QdrantClient, collection: str, dimension: int) -> None:
    """Create and verify a local cosine collection without an embedding provider."""

    if not collection.strip() or dimension < 1:
        raise IntelligenceConfigurationError("invalid Qdrant collection configuration")
    try:
        if not client.collection_exists(collection):
            created = client.create_collection(
                collection_name=collection,
                vectors_config=models.VectorParams(size=dimension, distance=models.Distance.COSINE),
            )
            if not created:
                raise IntelligenceUnavailableError("qdrant", "collection_create_failed")
        information = client.get_collection(collection)
    except _PROVIDER_ERRORS as error:
        raise IntelligenceUnavailableError("qdrant", "collection_unavailable") from error
    try:
        vectors = information.config.params.vectors
    except AttributeError as error:
        raise IntelligenceUnavailableError("qdrant", "malformed_collection_response") from error
    if not isinstance(vectors, models.VectorParams) or vectors.size != dimension:
        raise CollectionConfigurationError("dimension_mismatch")
    if vectors.distance != models.Distance.COSINE:
        raise CollectionConfigurationError("distance_mismatch")


class QdrantDocumentRetriever:
    """Store and retrieve bounded chunks while preserving the prompt trust boundary."""

    def __init__(
        self,
        client: QdrantClient,
        embeddings: EmbeddingModel,
        collection: str,
        *,
        min_score: float = 0.25,
        max_search_limit: int = 20,
        max_retrieved_text_bytes: int = MAX_RETRIEVED_TEXT_BYTES,
    ) -> None:
        normalized_collection = collection.strip()
        if not normalized_collection:
            raise ValueError("collection must not be blank")
        if not math.isfinite(min_score) or not 0 <= min_score <= 1:
            raise ValueError("min_score must be between 0 and 1")
        if type(max_search_limit) is not int or not 1 <= max_search_limit <= 100:
            raise ValueError("max_search_limit must be between 1 and 100")
        if (
            type(max_retrieved_text_bytes) is not int
            or not 1 <= max_retrieved_text_bytes <= MAX_CHUNK_BYTES * 100
        ):
            raise ValueError("max_retrieved_text_bytes is outside the supported range")
        self._client = client
        self._embeddings = embeddings
        self._collection = normalized_collection
        self._min_score = min_score
        self._max_search_limit = max_search_limit
        self._max_retrieved_text_bytes = max_retrieved_text_bytes

    def check_ready(self) -> None:
        """Fail explicitly when collection dimension or distance is incompatible."""

        try:
            information = self._client.get_collection(self._collection)
        except _PROVIDER_ERRORS as error:
            raise IntelligenceUnavailableError("qdrant", "collection_unavailable") from error
        try:
            vectors = information.config.params.vectors
        except AttributeError as error:
            raise IntelligenceUnavailableError("qdrant", "malformed_collection_response") from error
        if not isinstance(vectors, models.VectorParams):
            raise CollectionConfigurationError("collection must use one unnamed dense vector")
        if vectors.size != self._embeddings.dimension:
            raise CollectionConfigurationError(
                f"collection dimension {vectors.size} does not match "
                f"embedding dimension {self._embeddings.dimension}"
            )
        if vectors.distance is not models.Distance.COSINE:
            raise CollectionConfigurationError(
                f"collection distance {vectors.distance.value} does not match COSINE"
            )

    def ensure_collection(self) -> None:
        """Create the configured cosine collection once and verify existing collections."""

        try:
            exists = self._client.collection_exists(self._collection)
            if not exists:
                created = self._client.create_collection(
                    collection_name=self._collection,
                    vectors_config=models.VectorParams(
                        size=self._embeddings.dimension,
                        distance=models.Distance.COSINE,
                    ),
                )
                if not created:
                    raise IntelligenceUnavailableError("qdrant", "collection_create_failed")
        except _PROVIDER_ERRORS as error:
            raise IntelligenceUnavailableError("qdrant", "collection_create_failed") from error

        self.check_ready()
        try:
            for field_name, schema in _PAYLOAD_INDEXES:
                result = self._client.create_payload_index(
                    collection_name=self._collection,
                    field_name=field_name,
                    field_schema=schema,
                    wait=True,
                )
                _require_completed(result, "payload_index_not_completed")
        except _PROVIDER_ERRORS as error:
            raise IntelligenceUnavailableError("qdrant", "payload_index_failed") from error

    def upsert(
        self,
        chunks: Sequence[DocumentChunkInput],
        *,
        batch_size: int = 64,
    ) -> int:
        """Embed and synchronously upsert deterministic Qdrant points."""

        _validate_batch_size(batch_size)
        if not chunks:
            return 0
        return self._upsert_chunks(chunks, batch_size=batch_size, generations=None)

    def _upsert_chunks(
        self,
        chunks: Sequence[DocumentChunkInput],
        *,
        batch_size: int,
        generations: dict[UUID, UUID] | None,
    ) -> int:
        self.check_ready()
        completed = 0
        for start in range(0, len(chunks), batch_size):
            batch = chunks[start : start + batch_size]
            vectors = self._embed(tuple(chunk.text for chunk in batch))
            points = [
                models.PointStruct(
                    id=chunk.id,
                    vector=vector,
                    payload=_chunk_payload(
                        chunk,
                        generation_id=(
                            generations.get(chunk.document_id) if generations is not None else None
                        ),
                    ),
                )
                for chunk, vector in zip(batch, vectors, strict=True)
            ]
            try:
                result = self._client.upsert(
                    collection_name=self._collection,
                    points=points,
                    wait=True,
                )
            except _PROVIDER_ERRORS as error:
                raise IntelligenceUnavailableError("qdrant", "upsert_failed") from error
            _require_completed(result, "upsert_not_completed")
            completed += len(points)
        return completed

    def replace_documents(
        self,
        chunks: Sequence[DocumentChunkInput],
        *,
        batch_size: int = 64,
    ) -> int:
        """Upsert complete document generations, then remove their stale points.

        New points are written before generation-guarded cleanup, so a provider
        failure or concurrent writer cannot erase an unseen newer generation.
        """

        if not chunks:
            return 0
        _validate_batch_size(batch_size)
        grouped: dict[UUID, list[DocumentChunkInput]] = {}
        seen_ids: set[UUID] = set()
        for chunk in chunks:
            if chunk.id in seen_ids:
                raise ValueError("replacement chunks must have unique identifiers")
            seen_ids.add(chunk.id)
            grouped.setdefault(chunk.document_id, []).append(chunk)

        previous_points: dict[UUID, dict[str, str | None]] = {}
        snapshot_point_count = 0
        for document_id in grouped:
            document_points = self._snapshot_document_points(document_id)
            snapshot_point_count += len(document_points)
            if snapshot_point_count > _MAX_SNAPSHOT_POINTS_TOTAL:
                raise IntelligenceUnavailableError("qdrant", "replacement_snapshot_too_large")
            previous_points[document_id] = document_points
        generations = {document_id: uuid4() for document_id in grouped}
        completed = self._upsert_chunks(
            chunks,
            batch_size=batch_size,
            generations=generations,
        )
        for document_id, document_chunks in grouped.items():
            current_ids = {str(chunk.id) for chunk in document_chunks}
            stale_points = {
                identifier: generation
                for identifier, generation in previous_points[document_id].items()
                if identifier not in current_ids
            }
            by_generation: dict[str | None, list[str]] = {}
            for identifier, generation in stale_points.items():
                by_generation.setdefault(generation, []).append(identifier)
            for old_generation, identifiers in by_generation.items():
                for start in range(0, len(identifiers), _REPLACEMENT_PAGE_SIZE):
                    point_ids = identifiers[start : start + _REPLACEMENT_PAGE_SIZE]
                    conditions: list[models.Condition] = [
                        models.HasIdCondition(has_id=[UUID(value) for value in point_ids])
                    ]
                    if old_generation is None:
                        conditions.append(
                            models.IsEmptyCondition(
                                is_empty=models.PayloadField(key="generation_id")
                            )
                        )
                    else:
                        conditions.append(
                            models.FieldCondition(
                                key="generation_id",
                                match=models.MatchValue(value=old_generation),
                            )
                        )
                    selector = models.Filter(must=conditions)
                    self._delete_replaced_points(selector)
        return completed

    def _delete_replaced_points(self, selector: models.Filter) -> None:
        try:
            result = self._client.delete(
                collection_name=self._collection,
                points_selector=selector,
                wait=True,
                ordering=models.WriteOrdering.STRONG,
            )
        except _PROVIDER_ERRORS as error:
            raise IntelligenceUnavailableError("qdrant", "replacement_cleanup_failed") from error
        _require_completed(result, "replacement_cleanup_not_completed")

    def _snapshot_document_points(self, document_id: UUID) -> dict[str, str | None]:
        """Snapshot IDs and generations used to guard replacement cleanup."""

        scroll_filter = models.Filter(
            must=[
                models.FieldCondition(
                    key="document_id",
                    match=models.MatchValue(value=str(document_id)),
                )
            ]
        )
        points: dict[str, str | None] = {}
        offset: int | str | UUID | None = None
        seen_offsets: set[str] = set()
        page_count = 0
        while True:
            page_count += 1
            if page_count > _MAX_SNAPSHOT_PAGES:
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            try:
                response = self._client.scroll(
                    collection_name=self._collection,
                    scroll_filter=scroll_filter,
                    limit=_REPLACEMENT_PAGE_SIZE,
                    offset=offset,
                    with_payload=models.PayloadSelectorInclude(include=["generation_id"]),
                    with_vectors=False,
                )
            except _PROVIDER_ERRORS as error:
                raise IntelligenceUnavailableError(
                    "qdrant", "replacement_snapshot_failed"
                ) from error
            if not isinstance(response, tuple) or len(response) != 2:
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            records, next_offset = response
            if not isinstance(records, list):
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            if not records and next_offset is not None:
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            try:
                for record in records:
                    identifier = _validated_uuid(record.id)
                    payload = record.payload
                    if payload is not None and not isinstance(payload, dict):
                        raise ValueError("invalid snapshot payload")
                    raw_generation = payload.get("generation_id") if payload else None
                    generation = (
                        _validated_uuid(raw_generation) if raw_generation is not None else None
                    )
                    points[identifier] = generation
            except (AttributeError, ValueError) as error:
                raise IntelligenceUnavailableError(
                    "qdrant", "malformed_replacement_snapshot"
                ) from error
            if len(points) > _MAX_SNAPSHOT_POINTS_PER_DOCUMENT:
                raise IntelligenceUnavailableError("qdrant", "replacement_snapshot_too_large")
            if next_offset is None:
                return points
            if isinstance(next_offset, bool) or not isinstance(
                next_offset,
                (int, str, UUID),
            ):
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            if isinstance(next_offset, str) and not next_offset:
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            offset_key = repr(next_offset)
            if offset_key in seen_offsets:
                raise IntelligenceUnavailableError("qdrant", "malformed_replacement_snapshot")
            seen_offsets.add(offset_key)
            offset = next_offset

    def search(self, query: str, limit: int = 5) -> tuple[DocumentChunk, ...]:
        """Return scored payload text as data without constructing any model prompt."""

        normalized_query = query.strip()
        if not normalized_query:
            raise ValueError("query must not be blank")
        if len(normalized_query) > 2_000:
            raise ValueError("query must not exceed 2000 characters")
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be at least 1")
        bounded_limit = min(limit, self._max_search_limit)
        self.check_ready()
        vector = self._embed((normalized_query,))[0]
        try:
            response = self._client.query_points(
                collection_name=self._collection,
                query=vector,
                limit=bounded_limit,
                with_payload=models.PayloadSelectorInclude(include=_SEARCH_PAYLOAD_FIELDS),
                with_vectors=False,
                score_threshold=self._min_score,
            )
        except _PROVIDER_ERRORS as error:
            raise IntelligenceUnavailableError("qdrant", "search_failed") from error

        chunks: list[DocumentChunk] = []
        retrieved_text_bytes = 0
        try:
            points = response.points
        except AttributeError as error:
            raise IntelligenceUnavailableError("qdrant", "malformed_search_response") from error
        if not isinstance(points, list):
            raise IntelligenceUnavailableError("qdrant", "malformed_search_response")
        for point in points[:bounded_limit]:
            try:
                point_id = point.id
                score = point.score
                payload = point.payload
            except AttributeError as error:
                raise IntelligenceUnavailableError("qdrant", "malformed_search_payload") from error
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise IntelligenceUnavailableError("qdrant", "malformed_search_payload")
            numeric_score = float(score)
            if not math.isfinite(numeric_score) or numeric_score < 0 or numeric_score > 1.000_001:
                raise IntelligenceUnavailableError("qdrant", "malformed_search_payload")
            if numeric_score < self._min_score:
                continue
            chunk = _document_chunk_from_payload(
                payload,
                min(numeric_score, 1.0),
                point_id,
            )
            chunk_text_bytes = len(chunk.text.encode("utf-8"))
            if retrieved_text_bytes + chunk_text_bytes > self._max_retrieved_text_bytes:
                break
            chunks.append(chunk)
            retrieved_text_bytes += chunk_text_bytes
        return tuple(chunks)

    def _embed(self, texts: tuple[str, ...]) -> list[list[float]]:
        vectors = self._embeddings.embed(texts)
        if not isinstance(vectors, list):
            raise IntelligenceUnavailableError("embedding", "invalid_vector_count")
        if len(vectors) != len(texts):
            raise IntelligenceUnavailableError("embedding", "invalid_vector_count")
        for vector in vectors:
            if (
                not isinstance(vector, list)
                or len(vector) != self._embeddings.dimension
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    for value in vector
                )
            ):
                raise IntelligenceUnavailableError("embedding", "invalid_vector_shape")
        return [[float(value) for value in vector] for vector in vectors]


def _chunk_payload(
    chunk: DocumentChunkInput,
    *,
    generation_id: UUID | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": str(chunk.id),
        "document_id": str(chunk.document_id),
        "chunk_index": chunk.chunk_index,
        "text": chunk.text,
        "title": chunk.title,
        "source_path": chunk.source_path,
        "content_sha256": chunk.content_sha256,
    }
    if chunk.source_url is not None:
        payload["source_url"] = chunk.source_url
    if chunk.page is not None:
        payload["page"] = chunk.page
    if chunk.section is not None:
        payload["section"] = chunk.section
    if generation_id is not None:
        payload["generation_id"] = str(generation_id)
    return payload


def _document_chunk_from_payload(
    payload: object,
    score: float,
    expected_point_id: object,
) -> DocumentChunk:
    if not isinstance(payload, dict):
        raise IntelligenceUnavailableError("qdrant", "malformed_search_payload")
    try:
        identifier = _validated_uuid(payload["id"])
        if identifier != _validated_uuid(expected_point_id):
            raise ValueError("point identifier mismatch")
        text = _bounded_string(payload, "text", max_bytes=MAX_CHUNK_BYTES)
        if "\x00" in text:
            raise ValueError("invalid text")
        title = _bounded_string(payload, "title", max_characters=300, reject_control=True)
        source_url = _optional_bounded_string(payload, "source_url", max_characters=2_048)
        section = _optional_bounded_string(
            payload,
            "section",
            max_characters=500,
            reject_control=True,
        )
        if source_url is not None:
            parsed = urlsplit(source_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or _contains_control(source_url)
            ):
                raise ValueError("invalid source URL")
        page = payload.get("page")
        if page is not None and (
            isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 1_000_000
        ):
            raise ValueError("invalid page")
        return DocumentChunk(
            id=identifier,
            text=text,
            title=title,
            source_url=source_url,
            page=cast(int | None, page),
            section=section,
            score=score,
        )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise IntelligenceUnavailableError("qdrant", "malformed_search_payload") from error


def _bounded_string(
    payload: dict[object, object],
    key: str,
    *,
    max_characters: int | None = None,
    max_bytes: int | None = None,
    reject_control: bool = False,
) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid {key}")
    if max_characters is not None and len(value) > max_characters:
        raise ValueError(f"invalid {key}")
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"invalid {key}")
    if reject_control and _contains_control(value):
        raise ValueError(f"invalid {key}")
    return value


def _optional_bounded_string(
    payload: dict[object, object],
    key: str,
    *,
    max_characters: int,
    reject_control: bool = False,
) -> str | None:
    value = payload.get(key)
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"invalid {key}")
    if value is None:
        return None
    if len(value) > max_characters or (reject_control and _contains_control(value)):
        raise ValueError(f"invalid {key}")
    return value


def _validated_uuid(value: object) -> str:
    if not isinstance(value, (str, UUID)):
        raise ValueError("invalid point identifier")
    return str(UUID(str(value)))


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_batch_size(batch_size: int) -> None:
    if type(batch_size) is not int or not 1 <= batch_size <= 256:
        raise ValueError("batch_size must be between 1 and 256")


def _require_completed(result: object, reason: str) -> None:
    status = getattr(result, "status", None)
    if status != models.UpdateStatus.COMPLETED:
        raise IntelligenceUnavailableError("qdrant", reason)
