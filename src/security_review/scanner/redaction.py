"""Irreversible evidence redaction helpers."""

REDACTION_MARKER = "***REDACTED***"


def redact_match(line: str, span: tuple[int, int]) -> str:
    """Replace exactly one validated character span with a fixed marker."""

    start, end = span
    if start < 0 or end < start or end > len(line):
        raise ValueError("redaction span is outside the source line")
    return f"{line[:start]}{REDACTION_MARKER}{line[end:]}"
