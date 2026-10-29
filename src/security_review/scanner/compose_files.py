"""Shared recognition of Docker Compose configuration filenames."""

import re

COMPOSE_POLICY_VERSION = "2026.10.30.1"

_COMPOSE_BASENAME = re.compile(
    r"(?:docker-)?compose(?:\.[a-z0-9_.-]*)?\.ya?ml",
    re.ASCII | re.IGNORECASE,
)


def is_compose_file(path: str) -> bool:
    """Return whether a POSIX relative path has a recognized Compose basename."""
    return _COMPOSE_BASENAME.fullmatch(path.rsplit("/", 1)[-1]) is not None
