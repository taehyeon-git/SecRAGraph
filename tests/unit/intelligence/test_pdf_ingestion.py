"""PDF extraction is bounded and produces untrusted, page-cited evidence."""

from __future__ import annotations

import zlib
from io import BytesIO

import pytest
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from security_review.intelligence.pdf_ingestion import extract_pdf_pages


def _pdf(*pages: str) -> bytes:
    writer = PdfWriter()
    for text in pages:
        page = writer.add_blank_page(width=300, height=300)
        font = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }
        )
        page[NameObject("/Resources")] = DictionaryObject(
            {NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})}
        )
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 20 200 Td ({escaped}) Tj ET".encode())
        page[NameObject("/Contents")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_extracts_nonempty_pages_with_one_based_citations() -> None:
    documents = extract_pdf_pages(
        _pdf("first page", "second page"),
        source_path="standard.pdf",
        title="Standard",
        source_url="https://example.org/standard.pdf",
        corpus_id="official",
    )

    assert [(document.page, document.text) for document in documents] == [
        (1, "first page"),
        (2, "second page"),
    ]
    assert all(document.source_url == "https://example.org/standard.pdf" for document in documents)
    assert all(document.corpus_id == "official" for document in documents)


@pytest.mark.parametrize(("payload", "code"), [(b"not a PDF", "invalid_pdf")])
def test_rejects_unreadable_pdf_with_stable_content_free_code(payload: bytes, code: str) -> None:
    with pytest.raises(ValueError, match=code) as raised:
        extract_pdf_pages(
            payload,
            source_path="bad.pdf",
            title="Bad",
            source_url="https://example.org/bad.pdf",
            corpus_id="official",
        )
    assert "not a PDF" not in str(raised.value)


def test_rejects_pdf_without_extractable_text() -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    output = BytesIO()
    writer.write(output)

    with pytest.raises(ValueError, match="pdf_text_unavailable"):
        extract_pdf_pages(
            output.getvalue(),
            source_path="scan.pdf",
            title="Scan",
            source_url="https://example.org/scan.pdf",
            corpus_id="official",
        )


def test_rejects_encrypted_pdf() -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    writer.encrypt("local-test-password")
    output = BytesIO()
    writer.write(output)

    with pytest.raises(ValueError, match="encrypted_pdf"):
        extract_pdf_pages(
            output.getvalue(),
            source_path="encrypted.pdf",
            title="Encrypted",
            source_url="https://example.org/encrypted.pdf",
            corpus_id="official",
        )


def test_rejects_page_and_document_text_bounds() -> None:
    page_bound_pdf = _pdf("x" * 100_001)
    with pytest.raises(ValueError, match="pdf_text_too_large"):
        extract_pdf_pages(
            page_bound_pdf,
            source_path="large-page.pdf",
            title="Large page",
            source_url="https://example.org/large-page.pdf",
            corpus_id="official",
        )


def test_rejects_text_expanded_from_a_small_flate_stream() -> None:
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})}
    )
    uncompressed = b"BT /F1 12 Tf 20 200 Td " + b"(x) Tj " * 100_001 + b"ET"
    compressed = zlib.compress(uncompressed)
    assert len(compressed) < 2_000_000
    stream = DecodedStreamObject()
    stream.set_data(compressed)
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    page[NameObject("/Contents")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)

    with pytest.raises(ValueError, match="pdf_text_too_large"):
        extract_pdf_pages(
            output.getvalue(),
            source_path="compressed-expansion.pdf",
            title="Compressed expansion",
            source_url="https://example.org/compressed-expansion.pdf",
            corpus_id="official",
        )

    page_count_writer = PdfWriter()
    for _ in range(201):
        page_count_writer.add_blank_page(width=300, height=300)
    output = BytesIO()
    page_count_writer.write(output)
    with pytest.raises(ValueError, match="pdf_too_many_pages"):
        extract_pdf_pages(
            output.getvalue(),
            source_path="many-pages.pdf",
            title="Many pages",
            source_url="https://example.org/many-pages.pdf",
            corpus_id="official",
        )

    oversized_stream = _pdf("x" * 2_000_001)
    with pytest.raises(ValueError, match="pdf_text_too_large"):
        extract_pdf_pages(
            oversized_stream,
            source_path="large-stream.pdf",
            title="Large stream",
            source_url="https://example.org/large-stream.pdf",
            corpus_id="official",
        )


def test_rejects_raw_pdf_size_limit_before_parsing() -> None:
    with pytest.raises(ValueError, match="pdf_too_large"):
        extract_pdf_pages(
            b"x" * 5_000_001,
            source_path="large.pdf",
            title="Large",
            source_url="https://example.org/large.pdf",
            corpus_id="official",
        )
