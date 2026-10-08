"""Infrastructure-free upload metadata validation and bounded streaming."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_CHUNK_SIZE = 65_536


class UploadError(ValueError):
    """Upload rejection with a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class UploadPolicy:
    extensions: frozenset[str]
    content_types: frozenset[str]


FILE_UPLOAD_POLICY = UploadPolicy(
    extensions=frozenset({".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".ini"}),
    content_types=frozenset(
        {
            "application/json",
            "application/octet-stream",
            "application/toml",
            "application/x-yaml",
            "text/javascript",
            "text/plain",
            "text/x-python",
            "text/yaml",
        }
    ),
)
ZIP_UPLOAD_POLICY = UploadPolicy(
    extensions=frozenset({".zip"}),
    content_types=frozenset({"application/zip", "application/x-zip-compressed"}),
)


def _extension(filename: str) -> str:
    path = Path(filename)
    if path.name.lower() == ".env":
        return ".env"
    return path.suffix.lower()


def validate_upload_metadata(
    filename: str | None,
    content_type: str | None,
    policy: UploadPolicy,
) -> str:
    """Validate client-supplied metadata without using it as a filesystem path."""

    if filename is None or not filename.strip():
        raise UploadError("empty_filename")
    normalized = unicodedata.normalize("NFC", filename)
    if (
        normalized in {".", ".."}
        or normalized != Path(normalized).name
        or "/" in normalized
        or "\\" in normalized
        or ":" in normalized
        or normalized.endswith((" ", "."))
        or any(ord(character) < 32 for character in normalized)
    ):
        raise UploadError("unsafe_filename")
    normalized_type = (content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if (
        _extension(normalized) not in policy.extensions
        or normalized_type not in policy.content_types
    ):
        raise UploadError("unsupported_media_type")
    return normalized


def save_upload(stream: BinaryIO, destination: Path, max_bytes: int) -> Path:
    """Stream an upload to a new file while enforcing a strict byte cap."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with destination.open("xb") as target:
            created = True
            total = 0
            while chunk := stream.read(_CHUNK_SIZE):
                total += len(chunk)
                if total > max_bytes:
                    raise UploadError("upload_too_large")
                target.write(chunk)
    except FileExistsError as error:
        raise UploadError("destination_exists") from error
    except UploadError:
        if created:
            destination.unlink(missing_ok=True)
        raise
    except OSError as error:
        if created:
            destination.unlink(missing_ok=True)
        raise UploadError("upload_read_failed") from error
    return destination
