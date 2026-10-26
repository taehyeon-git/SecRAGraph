"""Bounded text extraction from explicitly selected, already verified PDF bytes."""

from __future__ import annotations

from io import BytesIO

from pypdf import PdfReader
from pypdf.generic import ArrayObject

from security_review.intelligence.ingestion import KnowledgeDocument

MAX_PDF_BYTES = 5_000_000
MAX_PDF_PAGES = 200
MAX_PAGE_TEXT_CHARACTERS = 100_000
MAX_PDF_TEXT_CHARACTERS = 2_000_000
MAX_PAGE_STREAM_BYTES = 2_000_000


def extract_pdf_pages(
    raw_pdf: bytes,
    *,
    source_path: str,
    title: str,
    source_url: str,
    corpus_id: str,
) -> tuple[KnowledgeDocument, ...]:
    """Extract nonempty pages without executing or logging PDF-supplied content."""

    if len(raw_pdf) > MAX_PDF_BYTES:
        raise ValueError("pdf_too_large")
    try:
        reader = PdfReader(BytesIO(raw_pdf), strict=True)
        if reader.is_encrypted:
            raise ValueError("encrypted_pdf")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise ValueError("pdf_too_many_pages")
        documents: list[KnowledgeDocument] = []
        total_characters = 0
        for page_number, page in enumerate(reader.pages, start=1):
            _check_raw_page_stream_size(page)
            text = page.extract_text(extraction_mode="plain") or ""
            if len(text) > MAX_PAGE_TEXT_CHARACTERS:
                raise ValueError("pdf_text_too_large")
            if not text.strip():
                continue
            total_characters += len(text)
            if total_characters > MAX_PDF_TEXT_CHARACTERS:
                raise ValueError("pdf_text_too_large")
            documents.append(
                KnowledgeDocument(
                    source_path=source_path,
                    title=title,
                    text=text,
                    source_url=source_url,
                    corpus_id=corpus_id,
                    page=page_number,
                )
            )
    except ValueError as error:
        if str(error) in {
            "encrypted_pdf",
            "pdf_too_large",
            "pdf_too_many_pages",
            "pdf_text_too_large",
        }:
            raise
        raise ValueError("invalid_pdf") from error
    except Exception as error:
        # Parser exceptions can contain attacker-controlled object names or content.
        raise ValueError("invalid_pdf") from error
    if not documents:
        raise ValueError("pdf_text_unavailable")
    return tuple(documents)


def _check_raw_page_stream_size(page: object) -> None:
    """Reject oversized raw streams without inflating encoded streams to inspect them."""

    contents = page.get("/Contents")  # type: ignore[attr-defined]
    if contents is None:
        return
    resolved = contents.get_object()
    streams = resolved if isinstance(resolved, ArrayObject) else (resolved,)
    total_bytes = 0
    for stream_reference in streams:
        stream = stream_reference.get_object()
        raw_data = getattr(stream, "_data", None)
        if isinstance(raw_data, bytes):
            total_bytes += len(raw_data)
            if total_bytes > MAX_PAGE_STREAM_BYTES:
                raise ValueError("pdf_text_too_large")
