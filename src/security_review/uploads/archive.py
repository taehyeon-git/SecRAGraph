"""Preflight-first ZIP extraction for untrusted uploaded archives."""

from __future__ import annotations

import shutil
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, ZipInfo

_CHUNK_SIZE = 65_536
_WINDOWS_RESERVED = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_WINDOWS_INVALID_CHARS = frozenset('<>:"|?*')
_SUPPORTED_COMPRESSION = frozenset({ZIP_STORED, ZIP_DEFLATED})


class UnsafeArchiveError(ValueError):
    """Archive rejection with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Hard limits enforced against metadata and streamed output."""

    max_files: int = 500
    max_extracted_bytes: int = 20_000_000
    max_path_depth: int = 32

    def __post_init__(self) -> None:
        if self.max_files < 1:
            raise ValueError("max_files must be positive")
        if self.max_extracted_bytes < 1:
            raise ValueError("max_extracted_bytes must be positive")
        if self.max_path_depth < 1:
            raise ValueError("max_path_depth must be positive")


@dataclass(frozen=True, slots=True)
class _ArchiveMember:
    info: ZipInfo
    path: PurePosixPath
    is_directory: bool

    @property
    def key(self) -> str:
        return self.path.as_posix().casefold()


def _unsafe_component(component: str) -> bool:
    stem = component.split(".", maxsplit=1)[0].casefold()
    return (
        not component
        or component.endswith((" ", "."))
        or any(character in _WINDOWS_INVALID_CHARS for character in component)
        or stem in _WINDOWS_RESERVED
        or any(ord(character) < 32 for character in component)
    )


def normalized_member_path(name: str) -> PurePosixPath:
    """Normalize a ZIP member into one portable, relative POSIX path."""

    if "\x00" in name:
        raise UnsafeArchiveError("unsafe_path")
    normalized = unicodedata.normalize("NFC", name.replace("\\", "/"))
    path = PurePosixPath(normalized)
    if (
        not path.parts
        or path.as_posix() == "."
        or path.is_absolute()
        or normalized.startswith("//")
        or ".." in path.parts
        or any(_unsafe_component(component) for component in path.parts)
    ):
        raise UnsafeArchiveError("unsafe_path")
    return path


def _is_directory(info: ZipInfo) -> bool:
    return info.is_dir() or info.filename.replace("\\", "/").endswith("/")


def _validate_entry_type(info: ZipInfo, is_directory: bool) -> None:
    if info.flag_bits & 0x1:
        raise UnsafeArchiveError("encrypted_entry")
    if info.compress_type not in _SUPPORTED_COMPRESSION:
        raise UnsafeArchiveError("unsupported_compression")
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFLNK:
        raise UnsafeArchiveError("link_entry")
    allowed_types = {0, stat.S_IFDIR if is_directory else stat.S_IFREG}
    if file_type not in allowed_types:
        raise UnsafeArchiveError("special_entry")


def _preflight(archive: ZipFile, limits: ArchiveLimits) -> tuple[_ArchiveMember, ...]:
    infos = archive.infolist()
    if len(infos) > limits.max_files:
        raise UnsafeArchiveError("too_many_files")

    members: list[_ArchiveMember] = []
    kinds: dict[str, bool] = {}
    total_size = 0
    for info in infos:
        path = normalized_member_path(info.filename)
        if len(path.parts) > limits.max_path_depth:
            raise UnsafeArchiveError("path_too_long")
        is_directory = _is_directory(info)
        _validate_entry_type(info, is_directory)
        member = _ArchiveMember(info=info, path=path, is_directory=is_directory)
        if member.key in kinds:
            raise UnsafeArchiveError("duplicate_path")
        kinds[member.key] = is_directory
        if not is_directory:
            total_size += info.file_size
            if total_size > limits.max_extracted_bytes:
                raise UnsafeArchiveError("archive_too_large")
        members.append(member)

    for member in members:
        parts = member.path.parts
        for length in range(1, len(parts)):
            parent_key = PurePosixPath(*parts[:length]).as_posix().casefold()
            if kinds.get(parent_key) is False:
                raise UnsafeArchiveError("path_collision")
    return tuple(sorted(members, key=lambda item: item.path.as_posix()))


def _extract_members(
    archive: ZipFile,
    members: tuple[_ArchiveMember, ...],
    staging: Path,
    limits: ArchiveLimits,
) -> tuple[PurePosixPath, ...]:
    extracted: list[PurePosixPath] = []
    total_written = 0
    for member in members:
        target = staging.joinpath(*member.path.parts)
        if member.is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        member_written = 0
        with archive.open(member.info, "r") as source, target.open("xb") as destination:
            while chunk := source.read(_CHUNK_SIZE):
                member_written += len(chunk)
                total_written += len(chunk)
                if total_written > limits.max_extracted_bytes:
                    raise UnsafeArchiveError("archive_too_large")
                destination.write(chunk)
        if member_written != member.info.file_size:
            raise UnsafeArchiveError("size_mismatch")
        extracted.append(member.path)
    return tuple(extracted)


def extract_zip_safely(
    archive: Path,
    destination: Path,
    limits: ArchiveLimits,
) -> tuple[Path, ...]:
    """Validate every ZIP member, then extract into a new destination atomically."""

    if destination.exists():
        raise UnsafeArchiveError("destination_exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(mkdtemp(prefix=".secragraph-extract-", dir=destination.parent))
    extracted: tuple[PurePosixPath, ...] = ()
    try:
        with ZipFile(archive, "r") as source:
            members = _preflight(source, limits)
            extracted = _extract_members(source, members, staging, limits)
        staging.replace(destination)
    except UnsafeArchiveError:
        raise
    except (BadZipFile, NotImplementedError, OSError, RuntimeError) as error:
        raise UnsafeArchiveError("invalid_archive") from error
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return tuple(destination.joinpath(*path.parts) for path in extracted)
