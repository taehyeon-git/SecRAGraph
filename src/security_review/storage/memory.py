"""Thread-safe in-memory report adapter for isolated tests."""

from __future__ import annotations

from threading import RLock
from uuid import UUID

from security_review.domain.models import ScanReport


class InMemoryReportRepository:
    """Implement the report port without external infrastructure."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._reports: dict[UUID, tuple[ScanReport, UUID | None]] = {}

    def save(self, report: ScanReport, *, owner_member_id: UUID | None = None) -> None:
        with self._lock:
            self._reports[report.scan_id] = (report, owner_member_id)

    def get(self, scan_id: UUID, *, owner_member_id: UUID | None = None) -> ScanReport | None:
        with self._lock:
            entry = self._reports.get(scan_id)
            if entry is None or (owner_member_id is not None and entry[1] != owner_member_id):
                return None
            return entry[0]
