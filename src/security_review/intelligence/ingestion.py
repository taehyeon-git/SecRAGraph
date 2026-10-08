"""Safe UTF-8 knowledge loading and deterministic paragraph-aware chunking."""

from __future__ import annotations

import json
import re
import stat
import unicodedata
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_DOCUMENT_BYTES = 5_000_000
MAX_TOTAL_BYTES = 20_000_000
MAX_DOCUMENTS = 500
MAX_DISCOVERY_ENTRIES = 10_000
MAX_CHUNK_BYTES = 32_000
MAX_CHUNKS_PER_DOCUMENT = 10_000
MAX_TOTAL_CHUNKS = 10_000
MAX_WORDS_PER_DOCUMENT = 250_000
MAX_CHUNK_WORDS = 2_000
MAX_OVERLAP_WORDS = 500

_DOCUMENT_NAMESPACE = uuid5(
    NAMESPACE_URL,
    "https://github.com/taehyeon-git/SecRAGraph/knowledge/document-v1",
)
_SUPPORTED_SUFFIXES = frozenset({".md", ".markdown"})
_ATX_HEADING = re.compile(r"^(?P<marks>#{1,6})[ \t]+(?P<title>.*?)[ \t]*#*[ \t]*$")
_FENCE = re.compile(r"^(?P<marker>`{3,}|~{3,})")


class DocumentIngestionError(ValueError):
    """A local knowledge document failed a bounded, content-safe validation."""

    def __init__(self, code: str, source_path: str | None = None) -> None:
        self.code = code
        self.source_path = _safe_display_path(source_path) if source_path else None
        suffix = f": {self.source_path}" if self.source_path else ""
        super().__init__(f"{code}{suffix}")


class KnowledgeDocument(BaseModel):
    """One validated document or pre-extracted PDF page supplied for ingestion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_path: str = Field(min_length=1, max_length=1_024)
    title: str = Field(min_length=1, max_length=300)
    text: str = Field(min_length=1, repr=False)
    source_url: str | None = Field(default=None, max_length=2_048)
    page: int | None = Field(default=None, ge=1, le=1_000_000)
    section: str | None = Field(default=None, max_length=500)

    @field_validator("source_path", mode="before")
    @classmethod
    def validate_source_path(cls, value: object) -> str:
        return _validated_source_path(value)

    @field_validator("title", "section", mode="before")
    @classmethod
    def normalize_short_text(cls, value: object) -> object:
        return _normalized_short_text(value)

    @field_validator("text", mode="before")
    @classmethod
    def normalize_document_text(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("text must be text")
        normalized = unicodedata.normalize(
            "NFC",
            value.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n"),
        ).strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("text must contain non-binary content")
        if len(normalized.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValueError("text exceeds the document byte limit")
        return normalized

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str | None) -> str | None:
        return _validated_source_url(value)


class DocumentChunkInput(BaseModel):
    """One deterministic, unscored chunk ready for an embedding store."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    document_id: UUID
    chunk_index: int = Field(ge=0)
    text: str = Field(min_length=1, repr=False)
    title: str = Field(min_length=1, max_length=300)
    source_path: str = Field(min_length=1, max_length=1_024)
    source_url: str | None = Field(default=None, max_length=2_048)
    page: int | None = Field(default=None, ge=1, le=1_000_000)
    section: str | None = Field(default=None, max_length=500)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("source_path", mode="before")
    @classmethod
    def validate_source_path(cls, value: object) -> str:
        return _validated_source_path(value)

    @field_validator("title", "section", mode="before")
    @classmethod
    def normalize_short_text(cls, value: object) -> object:
        return _normalized_short_text(value)

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str | None) -> str | None:
        return _validated_source_url(value)

    @model_validator(mode="after")
    def validate_content_digest_and_size(self) -> Self:
        encoded = self.text.encode("utf-8")
        if not self.text.strip() or "\x00" in self.text:
            raise ValueError("chunk must contain non-binary content")
        if len(encoded) > MAX_CHUNK_BYTES:
            raise ValueError("chunk exceeds the byte limit")
        expected = sha256(encoded, usedforsecurity=False).hexdigest()
        if self.content_sha256 != expected:
            raise ValueError("content_sha256 does not match text")
        return self


def chunk_document(
    document: KnowledgeDocument,
    chunk_size: int,
    overlap: int,
) -> tuple[DocumentChunkInput, ...]:
    """Split a document at section/paragraph boundaries with deterministic overlap."""

    _validate_chunk_limits(chunk_size, overlap)
    document_id = _document_id(document)
    digest_occurrences: Counter[str] = Counter()
    chunks: list[DocumentChunkInput] = []

    for section, paragraphs in _markdown_sections(
        document.text,
        document.section,
        document.title,
    ):
        tokens: list[tuple[str, int]] = []
        paragraph_ends: list[int] = []
        for paragraph_index, paragraph in enumerate(paragraphs):
            remaining_words = MAX_WORDS_PER_DOCUMENT - len(tokens)
            words = paragraph.split(maxsplit=remaining_words)
            if len(words) > remaining_words:
                raise DocumentIngestionError("too_many_words", document.source_path)
            tokens.extend((word, paragraph_index) for word in words)
            paragraph_ends.append(len(tokens))

        start = 0
        while start < len(tokens):
            cap = min(start + chunk_size, len(tokens))
            preferred = [
                boundary
                for boundary in paragraph_ends
                if start < boundary <= cap and boundary - start > overlap
            ]
            end = max(preferred, default=cap)
            text = _render_tokens(tokens[start:end])
            encoded = text.encode("utf-8")
            if len(encoded) > MAX_CHUNK_BYTES:
                raise DocumentIngestionError("chunk_too_large", document.source_path)
            digest = sha256(encoded, usedforsecurity=False).hexdigest()
            occurrence = digest_occurrences[digest]
            digest_occurrences[digest] += 1
            chunk_id = uuid5(document_id, f"chunk-v1:{digest}:{occurrence}")
            try:
                chunk = DocumentChunkInput(
                    id=chunk_id,
                    document_id=document_id,
                    chunk_index=len(chunks),
                    text=text,
                    title=document.title,
                    source_path=document.source_path,
                    source_url=document.source_url,
                    page=document.page,
                    section=section,
                    content_sha256=digest,
                )
            except ValidationError as error:
                raise DocumentIngestionError(
                    "invalid_chunk_metadata",
                    document.source_path,
                ) from error
            chunks.append(chunk)
            if len(chunks) > MAX_CHUNKS_PER_DOCUMENT:
                raise DocumentIngestionError("too_many_chunks", document.source_path)
            if end == len(tokens):
                break
            start = end - overlap

    if not chunks:
        raise DocumentIngestionError("empty_document", document.source_path)
    return tuple(chunks)


def chunk_documents(
    documents: tuple[KnowledgeDocument, ...],
    chunk_size: int,
    overlap: int,
    *,
    max_total_chunks: int = MAX_TOTAL_CHUNKS,
) -> tuple[DocumentChunkInput, ...]:
    """Chunk a corpus with one aggregate bound before any provider is called."""

    if type(max_total_chunks) is not int or not 1 <= max_total_chunks <= MAX_TOTAL_CHUNKS:
        raise ValueError("max_total_chunks is outside the supported range")
    chunks: list[DocumentChunkInput] = []
    for document in documents:
        document_chunks = chunk_document(document, chunk_size, overlap)
        if len(chunks) + len(document_chunks) > max_total_chunks:
            raise DocumentIngestionError("too_many_chunks")
        chunks.extend(document_chunks)
    return tuple(chunks)


def load_knowledge_documents(
    target: Path,
    *,
    max_document_bytes: int = MAX_DOCUMENT_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_documents: int = MAX_DOCUMENTS,
    max_discovery_entries: int = MAX_DISCOVERY_ENTRIES,
) -> tuple[KnowledgeDocument, ...]:
    """Load Markdown files without following links or accepting invalid UTF-8."""

    if not 1 <= max_document_bytes <= MAX_DOCUMENT_BYTES:
        raise ValueError("max_document_bytes is outside the supported range")
    if not 1 <= max_total_bytes <= MAX_TOTAL_BYTES:
        raise ValueError("max_total_bytes is outside the supported range")
    if not 1 <= max_documents <= MAX_DOCUMENTS:
        raise ValueError("max_documents is outside the supported range")
    if not 1 <= max_discovery_entries <= MAX_DISCOVERY_ENTRIES:
        raise ValueError("max_discovery_entries is outside the supported range")
    if _has_link_like_component(target):
        raise DocumentIngestionError("linked_path_not_allowed")
    try:
        resolved_target = target.resolve(strict=True)
    except OSError as error:
        raise DocumentIngestionError("path_unavailable") from error

    candidates: tuple[Path, ...]
    if resolved_target.is_file():
        if resolved_target.suffix.casefold() not in _SUPPORTED_SUFFIXES:
            raise DocumentIngestionError("unsupported_extension", resolved_target.name)
        root = resolved_target.parent
        candidates = (resolved_target,)
    elif resolved_target.is_dir():
        root = resolved_target
        discovered: list[Path] = []
        discovered_entries = 0
        for candidate in resolved_target.rglob("*"):
            discovered_entries += 1
            if discovered_entries > max_discovery_entries:
                raise DocumentIngestionError("too_many_entries")
            if _is_link_like(candidate):
                raise DocumentIngestionError(
                    "linked_path_not_allowed",
                    candidate.relative_to(root).as_posix(),
                )
            if candidate.is_file() and candidate.suffix.casefold() in _SUPPORTED_SUFFIXES:
                discovered.append(candidate)
        candidates = tuple(
            sorted(
                discovered,
                key=lambda item: (item.relative_to(root).as_posix().casefold(), item.as_posix()),
            )
        )
    else:
        raise DocumentIngestionError("path_must_be_file_or_directory")

    if not candidates:
        raise DocumentIngestionError("no_supported_documents")
    if len(candidates) > max_documents:
        raise DocumentIngestionError("too_many_documents")

    total_bytes = 0
    documents: list[KnowledgeDocument] = []
    seen_sources: set[str] = set()
    for candidate in candidates:
        source_path = (
            candidate.name if resolved_target.is_file() else candidate.relative_to(root).as_posix()
        )
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError as error:
            raise DocumentIngestionError("path_unavailable", source_path) from error
        if not resolved_candidate.is_relative_to(root):
            raise DocumentIngestionError("path_escape", source_path)
        try:
            with resolved_candidate.open("rb") as handle:
                payload = handle.read(max_document_bytes + 1)
        except OSError as error:
            raise DocumentIngestionError("read_failed", source_path) from error
        if len(payload) > max_document_bytes:
            raise DocumentIngestionError("document_too_large", source_path)
        total_bytes += len(payload)
        if total_bytes > max_total_bytes:
            raise DocumentIngestionError("total_size_exceeded")
        try:
            text = payload.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise DocumentIngestionError("invalid_utf8", source_path) from error

        title = _first_markdown_h1(text) or resolved_candidate.stem
        try:
            document = KnowledgeDocument(
                source_path=source_path,
                title=title,
                text=text,
            )
        except ValueError as error:
            raise DocumentIngestionError("invalid_document", source_path) from error
        normalized_source = document.source_path.casefold()
        if normalized_source in seen_sources:
            raise DocumentIngestionError("duplicate_source_path", document.source_path)
        seen_sources.add(normalized_source)
        documents.append(document)
    return tuple(documents)


def _validate_chunk_limits(chunk_size: int, overlap: int) -> None:
    if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_CHUNK_WORDS:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_WORDS}")
    if type(overlap) is not int or not 0 <= overlap < chunk_size:
        raise ValueError("overlap must be nonnegative and smaller than chunk_size")
    if overlap > MAX_OVERLAP_WORDS:
        raise ValueError(f"overlap must not exceed {MAX_OVERLAP_WORDS}")


def _document_id(document: KnowledgeDocument) -> UUID:
    identity = json.dumps(
        [
            "document-v1",
            document.source_path,
            document.source_url or "",
            document.page or 0,
            document.section or "",
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return uuid5(_DOCUMENT_NAMESPACE, identity)


def _markdown_sections(
    text: str,
    base_section: str | None,
    document_title: str,
) -> tuple[tuple[str | None, tuple[str, ...]], ...]:
    sections: list[tuple[str | None, tuple[str, ...]]] = []
    heading_stack: list[tuple[int, str]] = []
    current_section = base_section
    paragraphs: list[str] = []
    paragraph_lines: list[str] = []
    fence: tuple[str, int] | None = None

    def flush_paragraph() -> None:
        if not paragraph_lines:
            return
        normalized = " ".join("\n".join(paragraph_lines).split())
        paragraph_lines.clear()
        if normalized:
            paragraphs.append(normalized)

    def flush_section() -> None:
        flush_paragraph()
        if paragraphs:
            sections.append((current_section, tuple(paragraphs)))
            paragraphs.clear()

    for line in text.split("\n"):
        candidate = _markdown_candidate(line)
        if fence is not None:
            if candidate is not None and _is_closing_fence(candidate, fence):
                fence = None
            paragraph_lines.append(line.strip())
            continue

        fence_match = _FENCE.match(candidate or "")
        if fence_match:
            marker = fence_match.group("marker")
            fence = (marker[0], len(marker))
            paragraph_lines.append(line.strip())
            continue

        if candidate is not None:
            heading_match = _ATX_HEADING.match(candidate)
            if heading_match and heading_match.group("title").strip():
                flush_section()
                level = len(heading_match.group("marks"))
                title = " ".join(heading_match.group("title").split())
                if (
                    level == 1
                    and not heading_stack
                    and title.casefold() == document_title.casefold()
                ):
                    current_section = base_section
                    continue
                while heading_stack and heading_stack[-1][0] >= level:
                    heading_stack.pop()
                heading_stack.append((level, title))
                hierarchy = " > ".join(item[1] for item in heading_stack)
                current_section = f"{base_section} > {hierarchy}" if base_section else hierarchy
                continue
            if not candidate:
                flush_paragraph()
                continue
        paragraph_lines.append(line.strip())

    flush_section()
    return tuple(sections)


def _render_tokens(tokens: list[tuple[str, int]]) -> str:
    rendered: list[str] = []
    previous_paragraph: int | None = None
    for word, paragraph in tokens:
        if rendered:
            rendered.append("\n\n" if paragraph != previous_paragraph else " ")
        rendered.append(word)
        previous_paragraph = paragraph
    return "".join(rendered)


def _first_markdown_h1(text: str) -> str | None:
    fence: tuple[str, int] | None = None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        candidate = _markdown_candidate(line)
        if fence is not None:
            if candidate is not None and _is_closing_fence(candidate, fence):
                fence = None
            continue
        fence_match = _FENCE.match(candidate or "")
        if fence_match:
            marker = fence_match.group("marker")
            fence = (marker[0], len(marker))
            continue
        if candidate is not None:
            heading = _ATX_HEADING.match(candidate)
            if heading and len(heading.group("marks")) == 1:
                title = " ".join(heading.group("title").split())
                if title:
                    return title
    return None


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validated_source_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("source_path must be text")
    normalized = unicodedata.normalize("NFC", value.strip()).replace("\\", "/")
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.startswith("//")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or _contains_control(normalized)
    ):
        raise ValueError("source_path must be a safe relative path")
    return normalized


def _normalized_short_text(value: object) -> object:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("metadata must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if not normalized or _contains_control(normalized):
        raise ValueError("metadata must not be blank or contain control characters")
    return normalized


def _validated_source_url(value: str | None) -> str | None:
    if value is None:
        return None
    if _contains_control(value):
        raise ValueError("source_url must be an HTTP(S) URL without user information")
    normalized = unicodedata.normalize("NFC", value.strip())
    parsed = urlsplit(normalized)
    if (
        not normalized
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("source_url must be an HTTP(S) URL without user information")
    return normalized


def _safe_display_path(value: str, max_characters: int = 200) -> str:
    normalized = unicodedata.normalize("NFC", value)
    visible = "".join(
        character if not _contains_control(character) else "?" for character in normalized
    )
    return visible[:max_characters]


def _markdown_candidate(line: str) -> str | None:
    indentation_columns = 0
    content_start = 0
    for index, character in enumerate(line):
        if character == " ":
            indentation_columns += 1
        elif character == "\t":
            indentation_columns += 4 - (indentation_columns % 4)
        else:
            break
        content_start = index + 1
        if indentation_columns > 3:
            return None
    return line[content_start:].strip()


def _is_closing_fence(candidate: str, fence: tuple[str, int]) -> bool:
    marker, minimum_length = fence
    return re.fullmatch(rf"{re.escape(marker)}{{{minimum_length},}}[ \t]*", candidate) is not None


def _has_link_like_component(path: Path) -> bool:
    lexical = path if path.is_absolute() else Path.cwd() / path
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        if part == ".":
            continue
        if part == "..":
            current = current.parent
            continue
        current /= part
        if _is_link_like(current):
            return True
    return False


def _is_link_like(path: Path) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)
