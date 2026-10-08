"""Safe, bounded file discovery for untrusted source trees."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Literal

SkipReason = Literal[
    "binary_or_invalid_utf8",
    "candidate_limit_exceeded",
    "file_too_large",
    "max_files_exceeded",
    "outside_root",
    "symlink",
    "unreadable",
    "unsupported_extension",
]


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Resource limits applied before any source is inspected."""

    max_file_bytes: int = 1_000_000
    max_files: int = 500
    max_candidates: int = 10_000
    max_processing_seconds: float = 30.0
    allowed_extensions: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".ini"}
        )
    )
    excluded_directories: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__"}
        )
    )

    def __post_init__(self) -> None:
        if self.max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        if self.max_files < 1:
            raise ValueError("max_files must be positive")
        if self.max_candidates < 1:
            raise ValueError("max_candidates must be positive")
        if self.max_processing_seconds <= 0:
            raise ValueError("max_processing_seconds must be positive")


@dataclass(frozen=True, slots=True)
class ScannableFile:
    """A validated source candidate with a report-safe relative path."""

    path: Path = field(repr=False)
    root: Path = field(repr=False)
    relative_path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A source candidate excluded for a stable, machine-readable reason."""

    path: str
    reason: SkipReason


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Deterministically ordered accepted and rejected source candidates."""

    files: tuple[ScannableFile, ...]
    skipped: tuple[SkippedFile, ...]
    warnings: tuple[str, ...] = ()


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, OSError, ValueError):
        return False
    return True


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _extension(path: Path) -> str:
    if path.name.lower() == ".env":
        return ".env"
    return path.suffix.lower()


def _read_text(path: Path, max_file_bytes: int) -> tuple[str | None, SkipReason | None]:
    try:
        with path.open("rb") as source:
            payload = source.read(max_file_bytes + 1)
    except OSError:
        return None, "unreadable"
    if len(payload) > max_file_bytes:
        return None, "file_too_large"
    if b"\x00" in payload:
        return None, "binary_or_invalid_utf8"
    try:
        return payload.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "binary_or_invalid_utf8"


def _candidates(requested: Path) -> tuple[Path, Path]:
    if _is_link_like(requested):
        return requested.parent.absolute(), requested.absolute()
    resolved = requested.resolve(strict=True)
    if resolved.is_file():
        return resolved.parent, resolved
    if resolved.is_dir():
        return resolved, resolved
    raise ValueError("scan target must be a regular file or directory")


def _deadline_reached(deadline: float | None, clock: Callable[[], float]) -> bool:
    return deadline is not None and clock() >= deadline


def _directory_candidates(
    root: Path,
    limits: ScanLimits,
    deadline: float | None,
    clock: Callable[[], float],
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    candidates: list[Path] = []
    warnings: list[str] = []
    stopped = False

    def stop_with(code: str) -> None:
        nonlocal stopped
        if code not in warnings:
            warnings.append(code)
        stopped = True

    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        if _deadline_reached(deadline, clock):
            stop_with("processing_time_limit_exceeded")
            break
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            if _deadline_reached(deadline, clock):
                stop_with("processing_time_limit_exceeded")
                break
            child = current_path / name
            if name in limits.excluded_directories:
                continue
            if len(candidates) >= limits.max_candidates:
                stop_with("candidate_limit_exceeded")
                break
            if _is_link_like(child):
                candidates.append(child)
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories
        if stopped:
            break
        for name in sorted(file_names):
            if _deadline_reached(deadline, clock):
                stop_with("processing_time_limit_exceeded")
                break
            if len(candidates) >= limits.max_candidates:
                stop_with("candidate_limit_exceeded")
                break
            candidates.append(current_path / name)
        if stopped:
            break
    ordered = tuple(sorted(candidates, key=lambda item: _relative_path(item, root)))
    return ordered, tuple(warnings)


def discover_files(
    root: Path,
    limits: ScanLimits,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = monotonic,
) -> DiscoveryResult:
    """Discover bounded UTF-8 source files without following symbolic links."""

    scan_root, requested = _candidates(root)
    if _is_link_like(root):
        return DiscoveryResult(
            files=(),
            skipped=(SkippedFile(path=root.name, reason="symlink"),),
        )

    warnings: tuple[str, ...] = ()
    candidates: tuple[Path, ...]
    if requested.is_file():
        if _deadline_reached(deadline, clock):
            candidates = ()
            warnings = ("processing_time_limit_exceeded",)
        else:
            candidates = (requested,)
    else:
        candidates, warnings = _directory_candidates(
            requested,
            limits,
            deadline,
            clock,
        )

    allowed_extensions = {extension.lower() for extension in limits.allowed_extensions}
    files: list[ScannableFile] = []
    skipped: list[SkippedFile] = []
    for candidate in candidates:
        if _deadline_reached(deadline, clock):
            warnings = tuple(dict.fromkeys((*warnings, "processing_time_limit_exceeded")))
            break
        relative_path = _relative_path(candidate, scan_root)
        if _is_link_like(candidate):
            skipped.append(SkippedFile(path=relative_path, reason="symlink"))
            continue
        if not _inside_root(candidate, scan_root):
            skipped.append(SkippedFile(path=relative_path, reason="outside_root"))
            continue
        if _extension(candidate) not in allowed_extensions:
            skipped.append(SkippedFile(path=relative_path, reason="unsupported_extension"))
            continue
        try:
            size_bytes = candidate.stat().st_size
        except OSError:
            skipped.append(SkippedFile(path=relative_path, reason="unreadable"))
            continue
        if size_bytes > limits.max_file_bytes:
            skipped.append(SkippedFile(path=relative_path, reason="file_too_large"))
            continue
        if len(files) >= limits.max_files:
            skipped.append(SkippedFile(path=relative_path, reason="max_files_exceeded"))
            continue
        text, reason = _read_text(candidate, limits.max_file_bytes)
        if text is None:
            skipped.append(SkippedFile(path=relative_path, reason=reason or "unreadable"))
            continue
        files.append(
            ScannableFile(
                path=candidate,
                root=scan_root,
                relative_path=relative_path,
                size_bytes=size_bytes,
            )
        )
    return DiscoveryResult(files=tuple(files), skipped=tuple(skipped), warnings=warnings)


def read_scannable_text(file: ScannableFile, limits: ScanLimits) -> str | None:
    """Read a discovered file again, rejecting path or content changes safely."""

    if _is_link_like(file.path) or not _inside_root(file.path, file.root):
        return None
    text, _ = _read_text(file.path, limits.max_file_bytes)
    if text is None or _is_link_like(file.path) or not _inside_root(file.path, file.root):
        return None
    return text
