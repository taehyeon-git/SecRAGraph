"""Deterministic document loading and chunking contracts."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from security_review.intelligence.ingestion import (
    DocumentIngestionError,
    KnowledgeDocument,
    chunk_document,
    chunk_documents,
    load_knowledge_documents,
)


def _document(text: str, *, source_path: str = "guidelines.md") -> KnowledgeDocument:
    return KnowledgeDocument(
        source_path=source_path,
        title="Guidelines",
        text=text,
        source_url=None,
    )


def test_chunk_ids_are_stable_uuid_values_with_exact_word_overlap() -> None:
    document = _document("alpha beta gamma delta epsilon")

    first = chunk_document(document, chunk_size=3, overlap=1)
    second = chunk_document(document, chunk_size=3, overlap=1)

    assert [chunk.text for chunk in first] == [
        "alpha beta gamma",
        "gamma delta epsilon",
    ]
    assert [chunk.id for chunk in first] == [chunk.id for chunk in second]
    assert all(UUID(str(chunk.id)) == chunk.id for chunk in first)
    assert [chunk.chunk_index for chunk in first] == [0, 1]


def test_duplicate_chunk_content_gets_unique_but_repeatable_ids() -> None:
    document = _document("repeat this\n\nrepeat this")

    first = chunk_document(document, chunk_size=2, overlap=0)
    second = chunk_document(document, chunk_size=2, overlap=0)

    assert [chunk.text for chunk in first] == ["repeat this", "repeat this"]
    assert first[0].id != first[1].id
    assert [chunk.id for chunk in first] == [chunk.id for chunk in second]


def test_source_identity_changes_document_and_chunk_ids() -> None:
    first = chunk_document(_document("same evidence", source_path="a.md"), 10, 0)
    second = chunk_document(_document("same evidence", source_path="b.md"), 10, 0)

    assert first[0].document_id != second[0].document_id
    assert first[0].id != second[0].id


def test_equivalent_line_endings_and_whitespace_have_stable_chunks() -> None:
    windows = chunk_document(_document("alpha  beta\r\n\r\ngamma\tdelta"), 10, 0)
    unix = chunk_document(_document("alpha beta\n\ngamma delta"), 10, 0)

    assert [(chunk.id, chunk.text) for chunk in windows] == [
        (chunk.id, chunk.text) for chunk in unix
    ]


def test_paragraph_boundaries_are_preferred_before_word_fallback() -> None:
    chunks = chunk_document(
        _document("alpha beta\n\ngamma delta epsilon zeta"),
        chunk_size=4,
        overlap=1,
    )

    assert chunks[0].text == "alpha beta"
    assert all(len(chunk.text.split()) <= 4 for chunk in chunks)


def test_markdown_headings_become_metadata_and_overlap_never_crosses_sections() -> None:
    document = KnowledgeDocument(
        source_path="controls.md",
        title="Controls",
        text=(
            "# Authentication\n\nUse short lived tokens and verify issuers.\n\n"
            "## Secrets\n\nRotate exposed values immediately and audit access."
        ),
        source_url="https://example.com/controls",
        page=3,
        section="Platform",
    )

    chunks = chunk_document(document, chunk_size=6, overlap=2)

    assert {chunk.section for chunk in chunks} == {
        "Platform > Authentication",
        "Platform > Authentication > Secrets",
    }
    assert all(chunk.page == 3 for chunk in chunks)
    assert all(chunk.source_url == "https://example.com/controls" for chunk in chunks)
    assert not any("issuers" in chunk.text and "Rotate" in chunk.text for chunk in chunks)


def test_heading_inside_fenced_code_is_kept_as_document_text() -> None:
    chunks = chunk_document(
        _document("# Real\n\n```text\n# not-a-heading\nvalue\n```"),
        chunk_size=20,
        overlap=0,
    )

    assert chunks[0].section == "Real"
    assert "# not-a-heading" in chunks[0].text


def test_indented_code_and_fence_like_content_do_not_change_sections() -> None:
    chunks = chunk_document(
        _document(
            "# Real\n\n    # indented-code-heading\n\n"
            " \t# tab-indented-code-heading\n\n"
            "```text\n```not-a-closing-fence\n# fenced-heading\n```"
        ),
        chunk_size=30,
        overlap=0,
    )

    assert {chunk.section for chunk in chunks} == {"Real"}
    assert "# indented-code-heading" in chunks[0].text
    assert "# tab-indented-code-heading" in chunks[0].text
    assert "# fenced-heading" in chunks[0].text


def test_corpus_chunk_count_is_bounded_before_provider_calls() -> None:
    documents = (
        _document("one two", source_path="one.md"),
        _document("three four", source_path="two.md"),
    )

    with pytest.raises(DocumentIngestionError, match="too_many_chunks"):
        chunk_documents(documents, chunk_size=1, overlap=0, max_total_chunks=3)


def test_derived_section_validation_never_leaks_document_content() -> None:
    secret_heading = "TOPSECRET-" + "x" * 600

    with pytest.raises(DocumentIngestionError) as captured:
        chunk_document(_document(f"# Real\n\n## {secret_heading}\n\nevidence"), 20, 0)

    assert captured.value.code == "invalid_chunk_metadata"
    assert secret_heading not in str(captured.value)


@pytest.mark.parametrize(
    ("chunk_size", "overlap"),
    [(0, 0), (3, -1), (3, 3), (2_001, 0), (600, 501)],
)
def test_rejects_invalid_chunk_limits(chunk_size: int, overlap: int) -> None:
    with pytest.raises(ValueError):
        chunk_document(_document("evidence"), chunk_size, overlap)


@pytest.mark.parametrize("text", ["", " \n\t ", "\x00hidden"])
def test_rejects_empty_or_binary_document_text(text: str) -> None:
    with pytest.raises(ValueError):
        _document(text)


@pytest.mark.parametrize(
    "document_kwargs",
    [
        {"source_url": "https://example.com/path\nforged"},
        {"source_url": "https://example.com/path\x1bhidden"},
        {"page": 1_000_001},
    ],
)
def test_document_metadata_matches_the_retrieval_safety_contract(
    document_kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        KnowledgeDocument(
            source_path="guide.md",
            title="Guide",
            text="evidence",
            **document_kwargs,
        )


def test_control_characters_in_derived_sections_fail_with_a_safe_error() -> None:
    secret_section = "bad\x1bsection"

    with pytest.raises(DocumentIngestionError) as captured:
        chunk_document(_document(f"# Guide\n\n## {secret_section}\n\nevidence"), 20, 0)

    assert captured.value.code == "invalid_chunk_metadata"
    assert secret_section not in str(captured.value)


@pytest.mark.parametrize(
    "source_path",
    ["", "/absolute.md", "../escape.md", "C:\\escape.md", "folder/../../escape.md"],
)
def test_rejects_unsafe_source_identity(source_path: str) -> None:
    with pytest.raises(ValueError):
        _document("evidence", source_path=source_path)


def test_loader_is_utf8_strict_title_aware_and_deterministically_sorted(tmp_path: Path) -> None:
    (tmp_path / "z.md").write_text("# Zulu\n\nlast", encoding="utf-8", newline="\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "a.MD").write_text("# Alpha\n\nfirst", encoding="utf-8", newline="\n")
    (tmp_path / "ignored.txt").write_text("not indexed", encoding="utf-8")

    documents = load_knowledge_documents(tmp_path)

    assert [(item.source_path, item.title) for item in documents] == [
        ("nested/a.MD", "Alpha"),
        ("z.md", "Zulu"),
    ]


def test_loader_rejects_invalid_utf8_and_direct_non_markdown(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.md"
    invalid.write_bytes(b"\xff\xfe")
    with pytest.raises(DocumentIngestionError, match="invalid_utf8"):
        load_knowledge_documents(invalid)

    plain = tmp_path / "notes.txt"
    plain.write_text("plain", encoding="utf-8")
    with pytest.raises(DocumentIngestionError, match="unsupported_extension"):
        load_knowledge_documents(plain)


def test_loader_rejects_a_direct_symbolic_link(tmp_path: Path) -> None:
    document = tmp_path / "guide.md"
    document.write_text("# Guide\n\nevidence", encoding="utf-8")
    link = tmp_path / "linked.md"
    try:
        link.symlink_to(document)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(DocumentIngestionError, match="linked_path_not_allowed"):
        load_knowledge_documents(link)


def test_loader_rejects_source_paths_that_collide_after_unicode_normalization(
    tmp_path: Path,
) -> None:
    composed = tmp_path / "\u00e9.md"
    decomposed = tmp_path / "e\u0301.md"
    composed.write_text("# One\n\nevidence", encoding="utf-8")
    try:
        decomposed.write_text("# Two\n\nother evidence", encoding="utf-8")
    except OSError:
        pytest.skip("filesystem normalizes Unicode filenames")
    if len(tuple(tmp_path.glob("*.md"))) < 2:
        pytest.skip("filesystem normalizes Unicode filenames")

    with pytest.raises(DocumentIngestionError, match="duplicate_source_path"):
        load_knowledge_documents(tmp_path)


def test_loader_bounds_directory_discovery_entries(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"ignored-{index}.txt").write_text("ignored", encoding="utf-8")

    with pytest.raises(DocumentIngestionError, match="too_many_entries"):
        load_knowledge_documents(tmp_path, max_discovery_entries=2)


def test_loader_rejects_a_symbolic_link_in_an_ancestor_component(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "guide.md").write_text("# Guide\n\nevidence", encoding="utf-8")
    linked_directory = tmp_path / "linked-directory"
    try:
        linked_directory.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(DocumentIngestionError, match="linked_path_not_allowed"):
        load_knowledge_documents(linked_directory / "guide.md")


def test_loader_checks_link_components_before_processing_parent_segments(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    nested = outside / "nested"
    nested.mkdir(parents=True)
    (outside / "guide.md").write_text("# Outside\n\nevidence", encoding="utf-8")
    (tmp_path / "guide.md").write_text("# Lexical\n\nevidence", encoding="utf-8")
    linked_directory = tmp_path / "linked-directory"
    try:
        linked_directory.symlink_to(nested, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(DocumentIngestionError, match="linked_path_not_allowed"):
        load_knowledge_documents(linked_directory / ".." / "guide.md")
