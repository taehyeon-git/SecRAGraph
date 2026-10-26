"""Irreversible evidence redaction helpers."""

REDACTION_MARKER = "***REDACTED***"

_RULE_EVIDENCE = {
    "PY001": "Dynamic evaluation pattern detected; source omitted for privacy.",
    "PY002": "Shell execution pattern detected; source omitted for privacy.",
    "PY003": "Disabled TLS verification pattern detected; source omitted for privacy.",
    "PY004": "Unsafe YAML loader pattern detected; source omitted for privacy.",
    "PY005": "Dynamic SQL construction pattern detected; source omitted for privacy.",
    "PY006": "Pickle deserialization pattern detected; source omitted for privacy.",
    "JS001": "Disabled Node TLS verification pattern detected; source omitted for privacy.",
    "SEC001": f"Secret-like assignment detected: {REDACTION_MARKER}; source omitted for privacy.",
}


def safe_evidence(rule_id: str) -> str:
    """Return rule-owned evidence, never a substring of the scanned source."""

    return _RULE_EVIDENCE.get(rule_id, "Pattern detected; source omitted for privacy.")
