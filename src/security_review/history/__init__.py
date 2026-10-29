"""Trusted local Git history secret scanning."""

from security_review.history.engine import HistoryScanResult, scan_git_history

__all__ = ["HistoryScanResult", "scan_git_history"]
