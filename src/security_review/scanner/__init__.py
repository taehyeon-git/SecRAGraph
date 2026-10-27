"""Bounded, non-executing source discovery and scanner snapshots."""

from security_review.scanner.files import (
    DiscoveryResult,
    ScanLimits,
    ScannableFile,
    SkippedFile,
    discover_files,
    read_scannable_text,
)

__all__ = [
    "DiscoveryResult",
    "ScanLimits",
    "ScannableFile",
    "SkippedFile",
    "discover_files",
    "read_scannable_text",
]
