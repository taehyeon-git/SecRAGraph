"""Contracts for the portfolio's runnable examples and source boundaries."""

from __future__ import annotations

import re
from pathlib import Path

from click.utils import strip_ansi
from typer.testing import CliRunner

from security_review.cli import app

ROOT = Path(__file__).resolve().parents[3]
PORTFOLIO_FILES = (
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/text2sql-security.md",
    "docs/origins-and-credits.md",
    "docs/demo.md",
    "docs/images/.gitkeep",
)
READABLE_DOCS = tuple(path for path in PORTFOLIO_FILES if path.endswith(".md"))


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_readme_has_required_portfolio_sections() -> None:
    readme = _read("README.md")
    for heading in (
        "## 문제 정의",
        "## 핵심 아키텍처",
        "## LangGraph 워크플로",
        "## RAG와 Text2SQL",
        "## 빠른 시작",
        "## 테스트와 CI",
        "## 한계",
        "## 출처와 기여",
    ):
        assert heading in readme


def test_portfolio_artifacts_and_local_links_exist() -> None:
    for filename in PORTFOLIO_FILES:
        assert (ROOT / filename).is_file(), filename

    for filename in READABLE_DOCS:
        source = ROOT / filename
        for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", _read(filename)):
            destination = target.split("#", 1)[0]
            if not destination or "://" in destination or destination.startswith("mailto:"):
                continue
            assert (source.parent / destination).is_file(), f"{filename}: {target}"


def test_origin_repositories_and_license_scope_are_explicit() -> None:
    credits = _read("docs/origins-and-credits.md")
    assert "https://github.com/ye11an9/rag-documents" in credits
    assert "https://github.com/ye11an9/rag-documents/graphs/contributors" in credits
    assert "https://github.com/ye11an9/rag-documents/commit/05e1e98" in credits
    assert "https://github.com/ye11an9/rag-documents/commit/6ae53f1" in credits
    assert "https://github.com/taehyeon-git/security-agent-langgraph" in credits
    assert "새로 작성한 SecRAGraph 코드" in credits
    assert "재배포" in credits
    assert "MIT License" in _read("LICENSE")


def test_documented_cli_commands_and_options_appear_in_help() -> None:
    runner = CliRunner()
    examples = "\n".join(_read(path) for path in (*READABLE_DOCS, "docs/operations.md"))
    commands = re.findall(r"\bsecurity-review\s+([a-z][a-z-]*)([^\r\n]*)", examples)
    assert commands
    for command, rest_of_line in commands:
        result = runner.invoke(app, [command, "--help"], color=True)
        assert result.exit_code == 0, command
        help_output = strip_ansi(result.output)
        for option in re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest_of_line):
            assert option in help_output, f"{command}: {option}"


def test_readme_separates_focused_tests_from_live_integration_prerequisites() -> None:
    testing = (
        _read("README.md").split("## 테스트와 CI", maxsplit=1)[1].split("## 한계", maxsplit=1)[0]
    )
    assert "uv run pytest tests/unit/docs/test_documentation.py tests/e2e/test_cli.py" in testing
    assert re.search(r"(?m)^uv run pytest\s*$", testing) is None
    assert "tests/compose.integration.yaml" in testing
    assert "55432" in testing
    assert "56333" in testing
    assert "SECRAGRAPH_TEST_API_URL" in testing


def test_threat_model_and_text2sql_controls_cover_implemented_boundaries() -> None:
    threat_model = _read("docs/threat-model.md")
    for boundary in (
        "ZIP",
        "프롬프트 인젝션",
        "모델 출력",
        "로그",
        "CI 토큰",
        "클라우드",
    ):
        assert boundary in threat_model

    text2sql = _read("docs/text2sql-security.md")
    for control in (
        "SQLGlot",
        "intel.cwe",
        "intel.cve",
        "SET TRANSACTION READ ONLY",
        "LIMIT",
        "statement_timeout",
        "재시도",
    ):
        assert control in text2sql


def test_docs_and_examples_contain_no_live_key_shapes() -> None:
    patterns = (
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )
    files = [ROOT / path for path in READABLE_DOCS]
    files.extend(path for path in (ROOT / "examples").rglob("*") if path.is_file())
    for source in files:
        content = source.read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern.search(content) is None, source.relative_to(ROOT)
