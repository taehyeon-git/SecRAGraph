"""Manifest loading must validate the exact bytes later sent to ingestion."""

from __future__ import annotations

import json
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from security_review.config import Settings
from security_review.intelligence import manifest as manifest_module
from security_review.intelligence.ingestion import KnowledgeDocument, chunk_document
from security_review.intelligence.manifest import load_verified_corpus


def _manifest(
    root: Path, *, text: bytes = b"# Guide\n\nUse safe queries.\n", **changes: object
) -> Path:
    (root / "guide.md").write_bytes(text)
    entry: dict[str, object] = {
        "path": "guide.md",
        "publisher": "Example Project",
        "source_url": "https://example.com/guide",
        "license": "MIT",
        "source_revision": "test-revision-1",
        "source_date": "2026-10-09",
        "sha256": sha256(text).hexdigest(),
    }
    entry.update(changes)
    if Path(str(entry["path"])).suffix.casefold() == ".pdf":
        entry.setdefault("title", "Test PDF")
    path = root / "manifest.json"
    path.write_text(
        json.dumps({"version": 1, "corpus_id": "example-corpus", "documents": [entry]}),
        encoding="utf-8",
    )
    return path


def _text_pdf(text: str) -> bytes:
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
    stream = DecodedStreamObject()
    stream.set_data(f"BT /F1 12 Tf 20 200 Td ({text}) Tj ET".encode())
    page[NameObject("/Contents")] = writer._add_object(stream)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_valid_manifest_loads_verified_bytes_and_namespaces_chunk_ids(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    corpus = load_verified_corpus(tmp_path, manifest)

    assert corpus.corpus_id == "example-corpus"
    assert len(corpus.documents) == 1
    assert corpus.documents[0].text == "# Guide\n\nUse safe queries."
    assert corpus.documents[0].source_url == "https://example.com/guide"
    assert corpus.documents[0].corpus_id == "example-corpus"
    managed = chunk_document(corpus.documents[0], 20, 0)[0]
    legacy = chunk_document(
        KnowledgeDocument(source_path="guide.md", title="Guide", text=corpus.documents[0].text),
        20,
        0,
    )[0]
    assert managed.document_id != legacy.document_id
    assert managed.id != legacy.id


def test_valid_empty_manifest_is_a_previewable_empty_corpus(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "corpus_id": "example-corpus", "documents": []}),
        encoding="utf-8",
    )

    assert load_verified_corpus(tmp_path, manifest).documents == ()


def test_verified_snapshot_does_not_reopen_a_changed_source(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    corpus = load_verified_corpus(tmp_path, manifest)
    (tmp_path / "guide.md").write_text("# Replaced\n\nUnverified content", encoding="utf-8")

    assert "Use safe queries." in corpus.documents[0].text
    assert "Unverified content" not in corpus.documents[0].text


def test_manifest_extracts_only_hash_verified_pdf_pages(tmp_path: Path) -> None:
    payload = _text_pdf("PDF evidence")
    (tmp_path / "standard.pdf").write_bytes(payload)
    entry: dict[str, object] = {
        "path": "standard.pdf",
        "title": "Secure Software Development Framework, Version 1.1",
        "publisher": "NIST",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "license": "See publisher terms",
        "source_revision": "SP 800-218",
        "source_date": "2022-02-03",
        "sha256": sha256(payload).hexdigest(),
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "corpus_id": "official", "documents": [entry]}),
        encoding="utf-8",
    )

    corpus = load_verified_corpus(tmp_path, manifest)

    assert len(corpus.documents) == 1
    assert corpus.documents[0].page == 1
    assert corpus.documents[0].title == "Secure Software Development Framework, Version 1.1"
    assert corpus.documents[0].text == "PDF evidence"
    assert corpus.documents[0].source_url == entry["source_url"]
    assert corpus.entries[0].sha256 == sha256(payload).hexdigest()


def test_pdf_digest_mismatch_fails_before_parser_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _text_pdf("unverified PDF")
    manifest = _manifest(tmp_path, text=payload, path="standard.pdf", sha256="0" * 64)
    (tmp_path / "standard.pdf").write_bytes(payload)
    monkeypatch.setattr(
        manifest_module,
        "extract_pdf_pages",
        lambda *_args, **_kwargs: pytest.fail("unverified bytes reached PDF parser"),
    )

    with pytest.raises(ValueError, match="digest_mismatch"):
        load_verified_corpus(tmp_path, manifest)


def test_manifest_preserves_content_free_pdf_diagnostic_codes(tmp_path: Path) -> None:
    payload = b"not a PDF: private source content"
    manifest = _manifest(tmp_path, text=payload, path="bad.pdf")
    (tmp_path / "bad.pdf").write_bytes(payload)

    with pytest.raises(ValueError, match="invalid_pdf") as raised:
        load_verified_corpus(tmp_path, manifest)

    assert "private source content" not in str(raised.value)


def test_pdf_manifest_requires_publication_title(tmp_path: Path) -> None:
    payload = _text_pdf("PDF evidence")
    manifest = _manifest(tmp_path, text=payload, path="standard.pdf")
    (tmp_path / "standard.pdf").write_bytes(payload)
    content = json.loads(manifest.read_text(encoding="utf-8"))
    del content["documents"][0]["title"]
    manifest.write_text(json.dumps(content), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid_manifest"):
        load_verified_corpus(tmp_path, manifest)


def test_pdf_symlink_fails_before_parser_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "corpus"
    root.mkdir()
    payload = _text_pdf("linked PDF")
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(payload)
    try:
        (root / "linked.pdf").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    entry = {
        "path": "linked.pdf",
        "title": "Secure Software Development Framework, Version 1.1",
        "publisher": "NIST",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "license": "local review",
        "source_revision": "SP 800-218",
        "source_date": "2022-02-03",
        "sha256": sha256(payload).hexdigest(),
    }
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "corpus_id": "official", "documents": [entry]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        manifest_module,
        "extract_pdf_pages",
        lambda *_args, **_kwargs: pytest.fail("linked PDF reached parser"),
    )

    with pytest.raises(ValueError, match="linked_path_not_allowed"):
        load_verified_corpus(root, manifest)


def test_committed_demo_manifest_matches_its_project_authored_document() -> None:
    root = Path("data/knowledge")
    corpus = load_verified_corpus(root, root / "manifest.json")

    assert corpus.corpus_id == "secragraph-demo-v1"
    assert len(corpus.documents) == 1
    assert corpus.entries[0].publisher == "SecRAGraph project"


def test_invalid_manifest_fails_before_any_qdrant_provider_is_constructed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import qdrant_client

    from security_review.cli import _run_corpus_sync

    manifest = _manifest(tmp_path, sha256="0" * 64)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("provider must not be constructed")

    monkeypatch.setattr(qdrant_client, "QdrantClient", forbidden)
    with pytest.raises(ValueError, match="digest_mismatch"):
        _run_corpus_sync(tmp_path, manifest, Settings(testing=True), 20, 0, False, False)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"sha256": "0" * 64}, "digest_mismatch"),
        ({"path": "../outside.md"}, "invalid_manifest"),
        ({"source_url": "file:///etc/passwd"}, "invalid_manifest"),
        ({"license": ""}, "invalid_manifest"),
        ({"source_date": "2026-99-99"}, "invalid_manifest"),
    ],
)
def test_bad_manifest_or_changed_bytes_are_rejected(
    tmp_path: Path, changes: dict[str, object], expected: str
) -> None:
    manifest = _manifest(tmp_path, **changes)

    with pytest.raises(ValueError, match=expected):
        load_verified_corpus(tmp_path, manifest)


def test_duplicate_path_and_missing_source_are_rejected(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["documents"].append(payload["documents"][0])
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_verified_corpus(tmp_path, manifest)

    payload["documents"] = [payload["documents"][0]]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "guide.md").unlink()
    with pytest.raises(ValueError, match="source_unavailable"):
        load_verified_corpus(tmp_path, manifest)
