from io import BytesIO
from pathlib import Path

import pytest

from security_review.uploads.service import (
    FILE_UPLOAD_POLICY,
    ZIP_UPLOAD_POLICY,
    UploadError,
    save_upload,
    validate_upload_metadata,
)


class RecordingStream(BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


class RaisingStream(BytesIO):
    def read(self, size: int = -1) -> bytes:
        del size
        raise OSError("source disappeared")


class PartialRaisingStream(BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self._reads = 0

    def read(self, size: int = -1) -> bytes:
        del size
        self._reads += 1
        if self._reads == 1:
            return b"partial"
        raise OSError("source disappeared")


def test_save_upload_streams_bounded_chunks(tmp_path: Path) -> None:
    stream = RecordingStream(b"x" * 70_000)
    destination = tmp_path / "app.py"

    saved = save_upload(stream, destination, max_bytes=70_000)

    assert saved == destination
    assert destination.stat().st_size == 70_000
    assert stream.read_sizes
    assert all(0 < size <= 65_536 for size in stream.read_sizes)


def test_oversized_upload_removes_partial_destination(tmp_path: Path) -> None:
    destination = tmp_path / "app.py"

    with pytest.raises(UploadError, match="upload_too_large"):
        save_upload(BytesIO(b"x" * 11), destination, max_bytes=10)

    assert not destination.exists()


def test_stream_failure_removes_partial_destination(tmp_path: Path) -> None:
    destination = tmp_path / "app.py"

    with pytest.raises(UploadError, match="upload_read_failed"):
        save_upload(RaisingStream(b"data"), destination, max_bytes=10)

    assert not destination.exists()


def test_stream_failure_after_a_chunk_removes_partial_destination(tmp_path: Path) -> None:
    destination = tmp_path / "app.py"

    with pytest.raises(UploadError, match="upload_read_failed"):
        save_upload(PartialRaisingStream(), destination, max_bytes=10)

    assert not destination.exists()


def test_existing_upload_destination_is_not_overwritten_or_removed(tmp_path: Path) -> None:
    destination = tmp_path / "app.py"
    destination.write_bytes(b"keep")

    with pytest.raises(UploadError, match="destination_exists"):
        save_upload(BytesIO(b"replace"), destination, max_bytes=10)

    assert destination.read_bytes() == b"keep"


@pytest.mark.parametrize(
    ("filename", "content_type", "policy", "code"),
    [
        ("", "text/x-python", FILE_UPLOAD_POLICY, "empty_filename"),
        ("../app.py", "text/x-python", FILE_UPLOAD_POLICY, "unsafe_filename"),
        ("app.txt", "text/plain", FILE_UPLOAD_POLICY, "unsupported_media_type"),
        ("app.py", "application/zip", FILE_UPLOAD_POLICY, "unsupported_media_type"),
        ("source.zip", "text/plain", ZIP_UPLOAD_POLICY, "unsupported_media_type"),
    ],
)
def test_upload_metadata_rejects_mismatches(
    filename: str,
    content_type: str,
    policy: object,
    code: str,
) -> None:
    with pytest.raises(UploadError, match=code):
        validate_upload_metadata(filename, content_type, policy)  # type: ignore[arg-type]


def test_upload_metadata_accepts_supported_file() -> None:
    assert validate_upload_metadata("settings.py", "text/x-python", FILE_UPLOAD_POLICY) == (
        "settings.py"
    )
