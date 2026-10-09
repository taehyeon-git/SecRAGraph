import re
from dataclasses import replace
from pathlib import Path

import pytest

from security_review.application import scan_path
from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif
from security_review.scanner.engine import finding_id, scan_text
from security_review.scanner.files import ScanLimits
from security_review.scanner.rules import DEFAULT_RULES


def test_secret_is_absent_from_finding_dump() -> None:
    token = "sk-test-1234567890abcdef"

    findings = scan_text("settings.py", f'OPENAI_API_KEY = "{token}"\n')

    assert len(findings) == 1
    serialized = findings[0].model_dump_json()
    assert token not in serialized
    assert "***REDACTED***" in serialized


def test_every_secret_on_the_evidence_line_is_redacted() -> None:
    first = "first-secret-value"
    second = "second-secret-value"
    source = f'API_KEY="{first}"; PASSWORD="{second}"'

    findings = scan_text("settings.py", source)

    assert len(findings) == 1
    serialized = findings[0].model_dump_json()
    assert first not in serialized
    assert second not in serialized
    assert serialized.count("***REDACTED***") == 2


@pytest.mark.parametrize(
    ("path", "source"),
    [
        (
            "settings.py",
            'API_KEY = "demo-one-not-real-12345" # API_KEY = "demo-two-not-real-67890"',
        ),
        (
            "client.js",
            'const API_KEY = "demo-one-not-real-12345"; // PASSWORD = "demo-two-not-real-67890"',
        ),
        (
            "settings.py",
            'API_KEY = "demo-one-not-real-12345"; example = \'PASSWORD="demo-two-not-real-67890"\'',
        ),
    ],
)
def test_secret_evidence_redacts_skipped_same_line_matches_in_every_report(
    path: str, source: str
) -> None:
    findings = scan_text(path, source)
    assert len(findings) == 1
    report = build_report("sample", findings)

    for rendered in (
        findings[0].model_dump_json(),
        render_json(report),
        render_markdown(report),
        render_sarif(report),
    ):
        assert "demo-one-not-real-12345" not in rendered
        assert "demo-two-not-real-67890" not in rendered

    assert findings[0].redacted_evidence.count("***REDACTED***") == 2


@pytest.mark.parametrize(
    ("source", "rule_id", "cwe_id"),
    [
        ("eval(user_input)", "PY001", "CWE-95"),
        ("subprocess.run(cmd, shell=True)", "PY002", "CWE-78"),
        ("requests.get(url, verify=False)", "PY003", "CWE-295"),
    ],
)
def test_python_risk_rules(source: str, rule_id: str, cwe_id: str) -> None:
    finding = scan_text("app.py", source)[0]

    assert finding.rule_id == rule_id
    assert cwe_id in finding.cwe_ids


@pytest.mark.parametrize(
    "source",
    [
        'OPENAI_API_KEY = "short"',
        'OPENAI_API_KEY = "changeme"',
        'OPENAI_API_KEY = "your_api_key_here"',
    ],
)
def test_obvious_placeholder_or_short_secrets_are_ignored(source: str) -> None:
    assert scan_text("settings.py", source) == ()


def test_dotenv_secret_is_detected() -> None:
    findings = scan_text(".env", "GITHUB_TOKEN=ghp_example-but-long-enough")

    assert [item.rule_id for item in findings] == ["SEC001"]
    assert "ghp_example-but-long-enough" not in findings[0].model_dump_json()


@pytest.mark.parametrize(
    "source",
    [
        "api_key=runtime_key",
        "qdrant_api_key = settings.qdrant_api_key.get_secret_value()",
        "api_key: SecretStr | None = None",
        "def connect(*, api_key: str) -> None:",
    ],
)
def test_secret_rule_ignores_python_expressions_and_type_names(source: str) -> None:
    assert scan_text("client.py", source) == ()


def test_secret_rule_detects_hardcoded_keyword_argument() -> None:
    fake = "sk-test-example-value"
    findings = scan_text("client.py", f'connect(api_key="{fake}")')

    assert [item.rule_id for item in findings] == ["SEC001"]
    assert fake not in findings[0].model_dump_json()


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("settings.py", 'API_KEY = "sk-test-example-value"'),
        ("settings.py", 'API_KEY: str = "sk-test-example-value"'),
        ("client.js", 'const API_KEY = "sk-test-example-value";'),
        ("client.ts", 'const API_KEY: string = "sk-test-example-value";'),
        ("settings.yaml", "API_KEY: sk-test-example-value"),
        ("settings.json", '{"API_KEY": "sk-test-example-value"}'),
        ("settings.toml", 'API_KEY = "sk-test-example-value"'),
        (".env", "API_KEY=sk-test-example-value"),
    ],
)
def test_secret_rule_detects_literal_in_supported_languages(path: str, source: str) -> None:
    findings = scan_text(path, source)

    assert [item.rule_id for item in findings] == ["SEC001"]
    assert "sk-test-example-value" not in findings[0].model_dump_json()


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("settings.py", '# API_KEY = "sk-test-example-value"'),
        ("settings.py", 'answer = 42  # API_KEY = "sk-test-example-value"'),
        ("settings.py", "example = 'API_KEY = \"sk-test-example-value\"'"),
        ("client.js", "const example = 'API_KEY = \"sk-test-example-value\"';"),
        ("settings.py", 'api_key: "SecretStr"'),
        ("client.js", '// API_KEY = "sk-test-example-value"'),
        ("client.ts", 'const value = runtimeKey; // API_KEY = "sk-test-example-value"'),
    ],
)
def test_secret_rule_ignores_comments_and_examples(path: str, source: str) -> None:
    assert scan_text(path, source) == ()


def test_controlled_demo_secret_still_exercises_the_rule() -> None:
    fake = "demo-not-a-real-secret-12345"

    findings = scan_text("sample.py", f'DEMO_API_KEY = "{fake}"')

    assert [item.rule_id for item in findings] == ["SEC001"]
    assert fake not in repr(findings)


def test_rules_only_apply_to_supported_extensions() -> None:
    assert scan_text("notes.txt", "eval(user_input)") == ()


def test_finding_ids_and_order_are_stable() -> None:
    source = "eval(first)\nrequests.get(url, verify=False)\neval(second)"

    first = scan_text("app.py", source)
    second = scan_text("app.py", source)

    assert first == second
    assert [item.line_start for item in first] == [1, 2, 3]
    assert len({item.id for item in first}) == 3


def test_python_call_findings_use_call_start_line_and_redacted_evidence() -> None:
    from security_review.scanner.engine import scan_text_detailed

    source = (
        'API_KEY = "synthetic-key-1234567890"\n'
        "import subprocess\nsubprocess.run(\n    command,\n    shell=True,\n)\n"
    )

    result = scan_text_detailed("app.py", source)

    assert [(finding.rule_id, finding.line_start) for finding in result.findings] == [
        ("SEC001", 1),
        ("PY002", 3),
    ]
    assert result.warnings == ()
    assert "synthetic-key-1234567890" not in repr(result.findings)


def test_custom_python_regex_rule_still_runs() -> None:
    from security_review.scanner.engine import scan_text_detailed

    custom = replace(DEFAULT_RULES[0], rule_id="CUSTOM", pattern=re.compile(r"\bdangerous\s*\("))

    result = scan_text_detailed("app.py", "dangerous(input_value)\n", rules=(custom,))

    assert [(finding.rule_id, finding.line_start) for finding in result.findings] == [("CUSTOM", 1)]
    assert result.warnings == ()


def test_scan_path_keeps_secret_and_reports_python_parse_gap(tmp_path: Path) -> None:
    secret = "synthetic-key-1234567890"
    target = tmp_path / "broken.py"
    target.write_text(f'API_KEY = "{secret}"\nvalue = eval(\n', encoding="utf-8")

    report = scan_path(target, ScanLimits())

    assert [(finding.rule_id, finding.line_start) for finding in report.findings] == [("SEC001", 1)]
    assert "broken.py:python_syntax_error" in report.warnings
    assert secret not in report.model_dump_json()
    assert secret not in repr(report.warnings)


def test_detailed_scan_reports_early_deadline() -> None:
    from security_review.scanner.engine import scan_text_detailed

    result = scan_text_detailed("app.py", "eval(value)\n", should_stop=lambda: True)

    assert result.findings == ()
    assert result.warnings == ("processing_time_limit_exceeded",)


def test_detailed_scan_reports_deadline_reached_during_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security_review.scanner.python_calls as python_calls
    from security_review.scanner.engine import scan_text_detailed

    actual_parse = python_calls.ast.parse
    elapsed = [False]

    def finishing_parse(source: str) -> object:
        tree = actual_parse(source)
        elapsed[0] = True
        return tree

    with monkeypatch.context() as patcher:
        patcher.setattr(python_calls.ast, "parse", finishing_parse)
        result = scan_text_detailed("app.py", "eval(value)\n", should_stop=lambda: elapsed[0])

    assert result.findings == ()
    assert result.warnings == ("processing_time_limit_exceeded",)


def test_detailed_scan_reports_timeout_when_parse_fails_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import security_review.scanner.python_calls as python_calls
    from security_review.scanner.engine import scan_text_detailed

    actual_parse = python_calls.ast.parse
    elapsed = [False]

    def failing_parse(source: str, *args: object, **kwargs: object) -> object:
        if source == "eval(\n":
            elapsed[0] = True
        return actual_parse(source, *args, **kwargs)  # type: ignore[arg-type]

    with monkeypatch.context() as patcher:
        patcher.setattr(python_calls.ast, "parse", failing_parse)
        result = scan_text_detailed("app.py", "eval(\n", should_stop=lambda: elapsed[0])

    assert result.findings == ()
    assert result.warnings == ("processing_time_limit_exceeded",)


def test_node_tls_finding_uses_rule_metadata_redacted_evidence_and_stable_id() -> None:
    source = (
        'const API_KEY = "synthetic-key-1234567890"; '
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";'
    )

    findings = scan_text("settings.js", source)
    tls = next(finding for finding in findings if finding.rule_id == "JS001")
    rule = next(rule for rule in DEFAULT_RULES if rule.rule_id == "JS001")

    assert rule.pattern is None
    assert rule.extensions == frozenset({".js", ".ts", ".env"})
    assert (tls.category, tls.severity.value, tls.confidence.value, tls.cwe_ids) == (
        "configuration",
        "high",
        "high",
        ("CWE-295",),
    )
    assert "synthetic-key-1234567890" not in tls.model_dump_json()
    assert "***REDACTED***" in tls.redacted_evidence
    assert tls.id == finding_id("JS001", "settings.js", 1, tls.redacted_evidence)


def test_node_tls_findings_keep_crlf_line_numbers_and_deduplicate_same_line() -> None:
    source = (
        "const enabled = true;\r\n"
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; '
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\r\n'
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";\r\n'
    )

    findings = scan_text("settings.ts", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 2)]


def test_node_tls_public_scan_detects_literal_brackets_outside_non_code_text() -> None:
    source = (
        '// process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";\n'
        'const note = \'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"\';\n'
        'const pattern = /process.env\\["NODE_TLS_REJECT_UNAUTHORIZED"\\] = "0"/;\n'
        'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";\n'
        "process['env']['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;\n"
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [
        ("JS001", 4),
        ("JS001", 5),
    ]


@pytest.mark.parametrize("joiner", ["\u200c", "\u200d"])
def test_node_tls_public_scan_treats_joiner_as_identifier_continuation(joiner: str) -> None:
    source = (
        f'other{joiner}process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'
        f'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"\nin{joiner}value;\n'
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 2)]


def test_node_tls_public_scan_excludes_regex_and_continued_rhs() -> None:
    source = (
        "if (first) done(); "
        'else if (ok) /process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";/.test(s);\n'
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"\nin obj;\n'
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 4)]


def test_node_tls_public_scan_respects_else_regex_and_dollar_identifier() -> None:
    source = (
        'if (ok) work(); else /process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";/.test(s);\n'
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"\n'
        "in$foo;\n"
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 2)]


@pytest.mark.parametrize("private_name", ["else", "return", "in"])
def test_node_tls_public_scan_detects_assignment_after_private_keyword_division(
    private_name: str,
) -> None:
    source = (
        f"class X {{ #{private_name} = 2; m() {{ const x = this.#{private_name} / 2; "
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0; } }"
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 1)]


def test_node_tls_public_scan_detects_assignment_after_private_if_call_division() -> None:
    source = (
        "class X { #if(ok) { return ok; } m() { const x = this.#if(true) / 2; "
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0; } }"
    )

    findings = scan_text("settings.js", source)

    assert [(finding.rule_id, finding.line_start) for finding in findings] == [("JS001", 1)]


def test_node_tls_env_finding_is_part_of_scan_path(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("NODE_TLS_REJECT_UNAUTHORIZED=0\n", encoding="utf-8")

    report = scan_path(target, ScanLimits())

    assert [(finding.rule_id, finding.line_start) for finding in report.findings] == [("JS001", 1)]
