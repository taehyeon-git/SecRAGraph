"""Wait for one or more HTTP health endpoints with a bounded deadline."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import AbstractContextManager
from time import monotonic, sleep
from typing import Protocol, cast
from urllib.request import urlopen


class HealthResponse(Protocol):
    status: int


HealthOpener = Callable[[str, float], AbstractContextManager[HealthResponse]]


def _open(url: str, timeout: float) -> AbstractContextManager[HealthResponse]:
    response = urlopen(url, timeout=timeout)  # noqa: S310 - caller supplies explicit health URLs.
    return cast(AbstractContextManager[HealthResponse], response)


def wait_for_url(
    url: str,
    *,
    timeout_seconds: float = 60,
    interval_seconds: float = 0.5,
    opener: HealthOpener = _open,
) -> None:
    """Return after a healthy response or raise at the configured deadline."""

    if timeout_seconds < 0 or interval_seconds < 0:
        raise ValueError("timeouts must be non-negative")
    deadline = monotonic() + timeout_seconds
    while True:
        try:
            with opener(url, min(2.0, max(timeout_seconds, 0.1))) as response:
                if 200 <= response.status < 400:
                    return
        except OSError as error:
            if monotonic() >= deadline:
                raise TimeoutError(f"service did not become ready: {url}") from error
        if monotonic() >= deadline:
            raise TimeoutError(f"service did not become ready: {url}")
        sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="+", help="HTTP health endpoints to wait for")
    parser.add_argument("--timeout", type=float, default=60.0)
    arguments = parser.parse_args()
    for url in arguments.urls:
        wait_for_url(url, timeout_seconds=arguments.timeout)


if __name__ == "__main__":
    main()
