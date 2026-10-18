"""Manifest loading must validate the exact bytes later sent to ingestion."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from security_review.config import Settings
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
    path = root / "manifest.json"
    path.write_text(
        json.dumps({"version": 1, "corpus_id": "example-corpus", "documents": [entry]}),
        encoding="utf-8",
    )
    return path


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
