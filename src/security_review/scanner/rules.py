"""Immutable deterministic security-rule definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from security_review.domain.models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    """One deterministic source rule and its finding metadata."""

    rule_id: str
    category: str
    pattern: Pattern[str] | None
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    cwe_ids: tuple[str, ...]
    extensions: frozenset[str]
    redaction_group: str | int | None = None
    minimum_redacted_length: int = 0
    placeholder_pattern: Pattern[str] | None = None


_SOURCE_EXTENSIONS = frozenset(
    {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".ini"}
)
_PYTHON_EXTENSIONS = frozenset({".py"})
_PLACEHOLDER_PATTERN = re.compile(
    r"(?:change[-_]?me|example(?:[-_].*)?|your[-_].*|replace[-_]?me|dummy|placeholder|x{4,}|<.*>)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    ["']?
    (?P<key>
        (?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|CLIENT_SECRET)
        |AWS_SECRET_ACCESS_KEY
        |GITHUB_TOKEN
        |SECRET_KEY
    )
    ["']?
    \s*(?::\s*[A-Za-z_][A-Za-z0-9_.\[\], |]*\s*=|=|:)\s*
    (?P<secret>"[^"\r\n]+"|'[^'\r\n]+'|[^\s#;,}\]]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)

DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PY001",
        category="code_pattern",
        pattern=None,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        message="Dynamic evaluation can execute attacker-controlled code.",
        remediation="Replace eval with explicit parsing and an allowlist of supported operations.",
        cwe_ids=("CWE-95",),
        extensions=_PYTHON_EXTENSIONS,
    ),
    Rule(
        rule_id="PY002",
        category="code_pattern",
        pattern=None,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        message="Shell execution can allow operating-system command injection.",
        remediation="Pass an argument list without a shell and validate every untrusted argument.",
        cwe_ids=("CWE-78",),
        extensions=_PYTHON_EXTENSIONS,
    ),
    Rule(
        rule_id="PY003",
        category="code_pattern",
        pattern=None,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        message="TLS certificate verification is disabled.",
        remediation=(
            "Enable certificate verification and configure a trusted CA bundle if required."
        ),
        cwe_ids=("CWE-295",),
        extensions=_PYTHON_EXTENSIONS,
    ),
    Rule(
        rule_id="SEC001",
        category="secret",
        pattern=_SECRET_ASSIGNMENT_PATTERN,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        message="A secret-like value is assigned in source code.",
        remediation=(
            "Revoke exposed credentials and load replacements from an approved secret store."
        ),
        cwe_ids=("CWE-798",),
        extensions=_SOURCE_EXTENSIONS,
        redaction_group="secret",
        minimum_redacted_length=8,
        placeholder_pattern=_PLACEHOLDER_PATTERN,
    ),
)
