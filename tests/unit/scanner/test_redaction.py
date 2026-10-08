import pytest

from security_review.scanner.redaction import redact_match


def test_redact_match_replaces_only_the_sensitive_span() -> None:
    line = 'OPENAI_API_KEY = "sk-test-1234567890"'
    start = line.index('"')

    assert redact_match(line, (start, len(line))) == "OPENAI_API_KEY = ***REDACTED***"


@pytest.mark.parametrize("span", [(-1, 2), (3, 2), (0, 100)])
def test_redact_match_rejects_invalid_spans(span: tuple[int, int]) -> None:
    with pytest.raises(ValueError, match="span"):
        redact_match("secret", span)
