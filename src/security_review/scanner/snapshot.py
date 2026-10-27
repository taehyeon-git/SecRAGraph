"""Copy a bounded set of verified source files for isolated external scanners."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from security_review.scanner.files import DiscoveryResult, ScanLimits, read_scannable_text

_SCANNER_CONFIG_NAMES = frozenset(
    {
        ".semgrep.yml",
        ".semgrep.yaml",
        ".semgrepignore",
        ".checkov.yaml",
        ".checkov.yml",
        ".gitleaks.toml",
        ".gitleaksignore",
    }
)


@dataclass(frozen=True, slots=True)
class Snapshot:
    root: Path
    paths: tuple[str, ...]
    skipped: tuple[tuple[str, str], ...]


@contextmanager
def safe_snapshot(discovery: DiscoveryResult, limits: ScanLimits) -> Iterator[Snapshot]:
    """Materialize only accepted UTF-8 files; never copy target scanner settings."""

    staging_parent = os.environ.get("SECRAGRAPH_SNAPSHOT_TMPDIR")
    with TemporaryDirectory(prefix="secragraph-snapshot-", dir=staging_parent) as temporary:
        root = Path(temporary)
        paths: list[str] = []
        skipped: list[tuple[str, str]] = []
        total_bytes = 0
        for file in discovery.files:
            relative = PurePosixPath(file.relative_path)
            if relative.name.lower() in _SCANNER_CONFIG_NAMES:
                skipped.append((file.relative_path, "scanner_config_ignored"))
                continue
            text = read_scannable_text(file, limits)
            if text is None:
                skipped.append((file.relative_path, "file_changed_or_unreadable"))
                continue
            size = len(text.encode("utf-8"))
            if total_bytes + size > limits.max_total_bytes:
                skipped.append((file.relative_path, "aggregate_limit_exceeded"))
                continue
            target = root.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="")
            paths.append(file.relative_path)
            total_bytes += size
        yield Snapshot(root, tuple(paths), tuple(skipped))
