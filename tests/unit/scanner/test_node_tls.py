"""The narrow Node TLS rule recognizes literal disabling assignments only."""

from importlib import import_module

import pytest


def _detect(text: str, extension: str) -> tuple[int, ...]:
    detector = import_module("security_review.scanner.node_tls")
    return detector.detect_node_tls_assignments(text, extension)


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (".js", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'),
        (".ts", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
        (".js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;"),
        (".env", "NODE_TLS_REJECT_UNAUTHORIZED=0"),
        (".env", ' NODE_TLS_REJECT_UNAUTHORIZED = "0" # disabled'),
    ],
)
def test_detects_literal_zero_assignment(extension: str, source: str) -> None:
    assert _detect(source, extension) == (1,)


@pytest.mark.parametrize(
    ("extension", "source"),
    [
        (".js", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";'),
        (".js", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0" + suffix;'),
        (".js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0 || fallback;"),
        (".js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 00;"),
        (".js", '// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'),
        (".js", '/* process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; */'),
        (".js", 'const pattern = /process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"/;'),
        (".js", "const note = 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = \"0\"';"),
        (".js", "const note = `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`;"),
        (".js", 'other.process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'),
        (".js", 'process.env.NODE_TLS_REJECT_UNAUTHORIZED_EXTRA = "0";'),
        (".js", 'process.env.NOT_NODE_TLS_REJECT_UNAUTHORIZED = "0";'),
        (".js", 'const broken = "prefix"process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'),
        (".env", "NODE_TLS_REJECT_UNAUTHORIZED=1"),
        (".env", "# NODE_TLS_REJECT_UNAUTHORIZED=0"),
        (".env", "NODE_TLS_REJECT_UNAUTHORIZED_EXTRA=0"),
        (".env", "NODE_TLS_REJECT_UNAUTHORIZED=0suffix"),
        (".env", 'NODE_TLS_REJECT_UNAUTHORIZED="0"suffix'),
    ],
)
def test_ignores_non_literal_or_non_code_text(extension: str, source: str) -> None:
    assert _detect(source, extension) == ()


def test_comments_and_strings_do_not_hide_later_assignments() -> None:
    source = (
        '/* process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; */\r\n'
        'const note = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0";\r\n'
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\r\n'
    )

    assert _detect(source, ".ts") == (3,)


def test_regex_literal_after_if_condition_is_not_code() -> None:
    source = 'if (ok) /process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";/.test(s);'

    assert _detect(source, ".js") == ()


def test_postfix_division_does_not_hide_next_line_assignment() -> None:
    source = 'n++ / 2;\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'

    assert _detect(source, ".js") == (2,)


def test_postfix_division_does_not_hide_same_line_assignment() -> None:
    source = 'n++ / 2; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; /ok/.test(value);'

    assert _detect(source, ".js") == (1,)


def test_unterminated_regex_does_not_hide_following_line() -> None:
    source = 'const broken = /unfinished\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'

    assert _detect(source, ".js") == (2,)


@pytest.mark.parametrize(
    "source",
    [
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0" /* comment */;',
        'use(process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0");',
    ],
)
def test_detects_literal_zero_before_safe_trailing_syntax(source: str) -> None:
    assert _detect(source, ".ts") == (1,)


@pytest.mark.parametrize(
    "continuation",
    [
        ' /* comment */\n+ "1";',
        '\n+ "1";',
        ' // comment\n+ "1";',
        ' /* first line\n second line */\n+ "1";',
        '\n/* comment */ + "1";',
        "\n[0];",
    ],
)
def test_line_continuation_is_not_a_literal_zero_assignment(continuation: str) -> None:
    source = f'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"{continuation}'

    assert _detect(source, ".js") == ()


@pytest.mark.parametrize(
    "ending",
    [
        " /* comment\n continued */;",
        "\nconst done = true;",
        " // comment\nconst done = true;",
    ],
)
def test_new_statement_after_literal_zero_keeps_finding(ending: str) -> None:
    source = f'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"{ending}'

    assert _detect(source, ".js") == (1,)


def test_template_interpolation_is_unassessed() -> None:
    # This is a known coverage gap, not evidence that the interpolation is safe.
    source = 'const setup = `${process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"}`;'

    assert _detect(source, ".js") == ()


def test_unsupported_extension_is_not_assessed() -> None:
    assert _detect('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', ".py") == ()
