"""Run the full CI suite with a live API and guaranteed process cleanup."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from subprocess import DEVNULL, Popen, TimeoutExpired, run

from scripts.wait_for_services import wait_for_url

API_READY_URL = "http://127.0.0.1:8000/health/ready"
API_COMMAND = (
    sys.executable,
    "-m",
    "uvicorn",
    "apps.api.main:app",
    "--host",
    "127.0.0.1",
    "--port",
    "8000",
)
TEST_COMMAND = (
    sys.executable,
    "-m",
    "pytest",
    "--cov=security_review",
    "--cov-report=term-missing",
    "--cov-report=xml",
)


def run_full_suite(
    *,
    api_command: Sequence[str] = API_COMMAND,
    test_command: Sequence[str] = TEST_COMMAND,
    readiness_url: str = API_READY_URL,
) -> None:
    """Wait for the API, run every test, then stop the child on every path."""

    api = Popen(api_command, stdout=DEVNULL, stderr=DEVNULL)  # noqa: S603
    try:
        wait_for_url(readiness_url, timeout_seconds=60.0)
        run(test_command, check=True)  # noqa: S603
    finally:
        if api.poll() is None:
            api.terminate()
            try:
                api.wait(timeout=10)
            except TimeoutExpired:
                api.kill()
                api.wait(timeout=5)


if __name__ == "__main__":
    run_full_suite()
