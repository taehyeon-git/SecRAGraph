"""Thread-safe in-memory report adapter for isolated tests."""

from __future__ import annotations

from threading import RLock
from uuid import UUID

from security_review.domain.models import ScanReport


class InMemoryReportRepository:
    """Implement the report port without external infrastructure."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._reports: dict[UUID, ScanReport] = {}

    def save(self, report: ScanReport) -> None:
        with self._lock:
            self._reports[report.scan_id] = report

    def get(self, scan_id: UUID) -> ScanReport | None:
        with self._lock:
            return self._reports.get(scan_id)
