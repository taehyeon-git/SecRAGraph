"""Versioned, digest-verified local knowledge corpus manifests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from security_review.intelligence.ingestion import (
    MAX_DOCUMENT_BYTES,
    MAX_DOCUMENTS,
    MAX_TOTAL_BYTES,
    KnowledgeDocument,
    _first_markdown_h1,
    _has_link_like_component,
)
from security_review.intelligence.pdf_ingestion import extract_pdf_pages

MAX_MANIFEST_BYTES = 128_000


class ManifestError(ValueError):
    """Bounded error code with no document or manifest content in its message."""


class ManifestEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, max_length=1_024)
    title: str | None = Field(default=None, min_length=1, max_length=300)
    publisher: str = Field(min_length=1, max_length=300)
    source_url: str = Field(min_length=1, max_length=2_048)
    license: str = Field(min_length=1, max_length=100)
    source_revision: str = Field(min_length=1, max_length=200)
    source_date: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if (
            value.startswith("/")
            or "\\" in value
            or ":" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or Path(value).suffix.lower() not in {".md", ".markdown", ".pdf"}
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("unsafe source path")
        return value

    @field_validator("publisher", "license", "source_revision")
    @classmethod
    def validate_metadata(cls, value: str) -> str:
        if value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid source metadata")
        return value

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            value != value.strip()
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("invalid source URL")
        return value

    @field_validator("source_date")
    @classmethod
    def validate_source_date(cls, value: str) -> str:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError("invalid source date")
        date.fromisoformat(value)
        return value

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("invalid source title")
        return value

    @model_validator(mode="after")
    def require_pdf_title(self) -> Self:
        if Path(self.path).suffix.casefold() == ".pdf" and self.title is None:
            raise ValueError("PDF source title is required")
        return self


class CorpusManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(ge=1, le=1)
    corpus_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    documents: tuple[ManifestEntry, ...] = Field(max_length=MAX_DOCUMENTS)


@dataclass(frozen=True, slots=True)
class VerifiedCorpus:
    corpus_id: str
    documents: tuple[KnowledgeDocument, ...]
    entries: tuple[ManifestEntry, ...]
    manifest_sha256: str


def load_verified_corpus(root: Path, manifest_path: Path) -> VerifiedCorpus:
    """Validate a local manifest and construct documents from the exact verified bytes."""

    if _has_link_like_component(root) or _has_link_like_component(manifest_path):
        raise ManifestError("linked_path_not_allowed")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_manifest = manifest_path.resolve(strict=True)
        if not resolved_root.is_dir() or not resolved_manifest.is_file():
            raise ManifestError("source_unavailable")
        if not resolved_manifest.is_relative_to(resolved_root):
            raise ManifestError("invalid_manifest")
        with resolved_manifest.open("rb") as handle:
            raw_manifest = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise ManifestError("source_unavailable") from error
    if len(raw_manifest) > MAX_MANIFEST_BYTES:
        raise ManifestError("invalid_manifest")
    try:
        manifest = CorpusManifest.model_validate(json.loads(raw_manifest.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
        raise ManifestError("invalid_manifest") from error

    seen_paths: set[str] = set()
    documents: list[KnowledgeDocument] = []
    total_bytes = 0
    for entry in manifest.documents:
        folded_path = entry.path.casefold()
        if folded_path in seen_paths:
            raise ManifestError("duplicate_source_path")
        seen_paths.add(folded_path)
        candidate = resolved_root / entry.path
        if _has_link_like_component(candidate):
            raise ManifestError("linked_path_not_allowed")
        try:
            resolved_candidate = candidate.resolve(strict=True)
            if (
                not resolved_candidate.is_relative_to(resolved_root)
                or not resolved_candidate.is_file()
            ):
                raise ManifestError("invalid_manifest")
            with resolved_candidate.open("rb") as handle:
                raw_document = handle.read(MAX_DOCUMENT_BYTES + 1)
        except OSError as error:
            raise ManifestError("source_unavailable") from error
        if len(raw_document) > MAX_DOCUMENT_BYTES:
            raise ManifestError("document_too_large")
        total_bytes += len(raw_document)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ManifestError("total_size_exceeded")
        if sha256(raw_document).hexdigest() != entry.sha256:
            raise ManifestError("digest_mismatch")
        try:
            if resolved_candidate.suffix.casefold() == ".pdf":
                documents.extend(
                    extract_pdf_pages(
                        raw_document,
                        source_path=entry.path,
                        title=entry.title or resolved_candidate.stem,
                        source_url=entry.source_url,
                        corpus_id=manifest.corpus_id,
                    )
                )
            else:
                decoded = raw_document.decode("utf-8-sig")
                documents.append(
                    KnowledgeDocument(
                        source_path=entry.path,
                        title=_first_markdown_h1(decoded) or resolved_candidate.stem,
                        text=decoded,
                        source_url=entry.source_url,
                        corpus_id=manifest.corpus_id,
                    )
                )
        except ValueError as error:
            code = str(error)
            if code in {
                "encrypted_pdf",
                "invalid_pdf",
                "pdf_text_too_large",
                "pdf_text_unavailable",
                "pdf_too_large",
                "pdf_too_many_pages",
            }:
                raise ManifestError(code) from error
            raise ManifestError("invalid_document") from error
        except (UnicodeDecodeError, ValidationError) as error:
            raise ManifestError("invalid_document") from error
    return VerifiedCorpus(
        corpus_id=manifest.corpus_id,
        documents=tuple(documents),
        entries=manifest.documents,
        manifest_sha256=sha256(raw_manifest).hexdigest(),
    )
