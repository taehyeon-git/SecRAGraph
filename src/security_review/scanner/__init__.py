"""Bounded, non-executing source discovery and deterministic scanning."""

from security_review.scanner.engine import scan_text
from security_review.scanner.files import (
    DiscoveryResult,
    ScanLimits,
    ScannableFile,
    SkippedFile,
    discover_files,
    read_scannable_text,
)
from security_review.scanner.redaction import REDACTION_MARKER, redact_match
from security_review.scanner.rules import DEFAULT_RULES, Rule

__all__ = [
    "DEFAULT_RULES",
    "DiscoveryResult",
    "REDACTION_MARKER",
    "Rule",
    "ScanLimits",
    "ScannableFile",
    "SkippedFile",
    "discover_files",
    "redact_match",
    "read_scannable_text",
    "scan_text",
]
