import pytest

from security_review.reporting.builder import build_report
from security_review.reporting.json_report import render_json
from security_review.reporting.markdown import render_markdown
from security_review.reporting.sarif import render_sarif
from security_review.scanner.engine import scan_text


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
