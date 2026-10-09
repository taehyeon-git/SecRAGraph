"""Observable contracts for reproducible offline RAG evidence files."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_review.evaluation.offline_rag import run_rag_evaluation
from security_review.evaluation.rag_models import RagEvaluation

ROOT = Path(__file__).resolve().parents[3]
CASES = ROOT / "data/evaluation/rag_cases.json"
GUIDE = ROOT / "data/knowledge/secragraph-security-guidelines.md"


@pytest.fixture(scope="module")
def evaluation() -> RagEvaluation:
    return run_rag_evaluation(CASES, GUIDE)


def test_repeated_evaluation_renders_identical_complete_artifacts(
    evaluation: RagEvaluation,
) -> None:
    from security_review.evaluation.rag_render import render_rag_json, render_rag_markdown

    second = run_rag_evaluation(CASES, GUIDE)
    json_text = render_rag_json(evaluation)
    markdown = render_rag_markdown(evaluation)

    assert json_text.encode("utf-8") == render_rag_json(second).encode("utf-8")
    assert markdown.encode("utf-8") == render_rag_markdown(second).encode("utf-8")
    assert json_text.endswith("\n") and markdown.endswith("\n")
    payload = json.loads(json_text)
    assert list(payload) == sorted(payload)
    assert payload["manifest_sha256"] == evaluation.manifest_sha256
    assert payload["corpus_sha256"] == evaluation.corpus_sha256
    assert payload["corpus_digest_kind"] == "indexed-chunks-v1"
    assert payload["embedding_algorithm_version"] == evaluation.embedding_algorithm_version
    assert payload["source_fingerprint"] == evaluation.source_fingerprint
    for value in (
        evaluation.manifest_sha256,
        evaluation.corpus_sha256,
        evaluation.embedding_algorithm_version,
        evaluation.source_fingerprint,
        "indexed-chunks-v1",
    ):
        assert value in markdown
    assert "not raw guide file bytes" in markdown
    assert "denominator" in markdown.lower()


def test_rendering_exposes_only_bounded_cited_text_and_escapes_markdown(
    evaluation: RagEvaluation,
) -> None:
    from security_review.evaluation.rag_render import render_rag_json, render_rag_markdown

    payload = json.loads(render_rag_json(evaluation))
    assert all(
        set(source) == {"id", "title", "source_url", "page", "section", "score"}
        for case in payload["cases"]
        for source in case["retrieved"]
    )
    assert all(
        len(source["excerpt"]) <= 240
        for case in payload["cases"]
        for source in case["cited_evidence"]
    )
    assert '"chunks"' not in json.dumps(payload)
    assert '"messages"' not in json.dumps(payload)
    assert "A document can contain phrases such as" not in render_rag_json(evaluation)
    markdown = render_rag_markdown(evaluation)
    assert "A document can contain phrases such as" not in markdown
    retrieved_section = markdown.split("#### Retrieved candidates (metadata only)", maxsplit=1)[1]
    retrieved_section = retrieved_section.split("#### Cited evidence", maxsplit=1)[0]
    assert "score:" in retrieved_section

    first = evaluation.cases[0]
    poisoned_evidence = first.cited_evidence[0].model_copy(
        update={"excerpt": "<script>bad</script> [source:fake] | *"}
    )
    poisoned_case = first.model_copy(update={"cited_evidence": (poisoned_evidence,)})
    poisoned = evaluation.model_copy(update={"cases": (poisoned_case, *evaluation.cases[1:])})
    markdown = render_rag_markdown(poisoned)
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\[source:fake\\]" in markdown
    assert "\\|" in markdown


def test_real_command_writes_parseable_json_and_markdown(tmp_path: Path) -> None:
    # The current interpreter and module name are fixed; shell expansion is disabled.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "scripts.run_rag_evidence", "--output-dir", str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    json_path = tmp_path / "rag.json"
    markdown_path = tmp_path / "rag.md"
    assert json_path.stat().st_size > 0
    assert markdown_path.stat().st_size > 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["manifest_sha256"] in markdown_path.read_text(encoding="utf-8")


def test_malformed_output_path_has_safe_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.run_rag_evidence import main

    occupied = tmp_path / "occupied"
    occupied.write_text("keep", encoding="utf-8")

    assert main(["--output-dir", str(occupied)]) == 2
    output = capsys.readouterr()
    assert "Unable to write RAG evidence files." in output.err
    assert str(occupied) not in output.err
    assert "Traceback" not in output.err
    assert occupied.read_text(encoding="utf-8") == "keep"


def test_failed_label_exits_nonzero_and_preserves_evidence(tmp_path: Path) -> None:
    manifest = json.loads(CASES.read_text(encoding="utf-8"))
    manifest["cases"][0]["expected_retrieved_section"] = "A deliberately absent section"
    cases_path = tmp_path / "failed_cases.json"
    cases_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_dir = tmp_path / "out"

    # The current interpreter and module name are fixed; paths remain data arguments.
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "scripts.run_rag_evidence",
            "--cases",
            str(cases_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 1, result.stderr
    assert json.loads((output_dir / "rag.json").read_text(encoding="utf-8"))["passed"] is False
    assert "FAIL" in (output_dir / "rag.md").read_text(encoding="utf-8")
