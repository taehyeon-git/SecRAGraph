from __future__ import annotations

from types import TracebackType
from urllib.error import URLError

import pytest

from scripts.wait_for_services import wait_for_url


class HealthyResponse:
    status = 200

    def __enter__(self) -> HealthyResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback


def test_wait_for_url_retries_until_service_is_healthy() -> None:
    attempts = 0

    def opener(url: str, timeout: float) -> HealthyResponse:
        nonlocal attempts
        del url, timeout
        attempts += 1
        if attempts == 1:
            raise URLError("starting")
        return HealthyResponse()

    wait_for_url(
        "http://service/health",
        timeout_seconds=1,
        interval_seconds=0,
        opener=opener,
    )

    assert attempts == 2


def test_wait_for_url_raises_after_deadline() -> None:
    def opener(url: str, timeout: float) -> HealthyResponse:
        del url, timeout
        raise URLError("offline")

    with pytest.raises(TimeoutError, match="service did not become ready"):
        wait_for_url(
            "http://service/health",
            timeout_seconds=0,
            interval_seconds=0,
            opener=opener,
        )
