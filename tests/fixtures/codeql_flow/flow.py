"""Cross-file forwarding and explicit allowlist sanitizer for CodeQL."""

from codeql_flow.sink import observe


def forward(value: str) -> str:
    return observe(value)


def allowlisted(value: str) -> str:
    if (
        value
        and len(value) <= 32
        and all(char.isascii() and (char.isalnum() or char == "_") for char in value)
    ):
        return value
    return ""
