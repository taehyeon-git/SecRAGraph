import stat
import warnings
from pathlib import Path
from zipfile import ZIP_BZIP2, ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from security_review.uploads.archive import ArchiveLimits, UnsafeArchiveError, extract_zip_safely


def make_zip(path: Path, entries: list[tuple[str | ZipInfo, bytes]]) -> Path:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
            for name, payload in entries:
                archive.writestr(name, payload)
    return path


@pytest.mark.parametrize(
    "member_name",
    [
        "../escape.py",
        "/absolute.py",
        "C:/windows.py",
        "safe/../../escape.py",
        "//server/share.py",
        "safe/file.py:stream",
        "safe/trailing. ",
        "C:drive-relative.py",
        "safe/CON.py",
        "safe/clock$.txt",
        "safe/question?.py",
        'safe/quote".py',
    ],
)
def test_rejects_escaping_or_ambiguous_archive_members(
    tmp_path: Path,
    member_name: str,
) -> None:
    archive = make_zip(tmp_path / "payload.zip", [(member_name, b"print('x')")])
    destination = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="unsafe_path"):
        extract_zip_safely(archive, destination, ArchiveLimits())

    assert not destination.exists()


@pytest.mark.parametrize(
    "names",
    [
        ("src/app.py", "src\\app.py"),
        ("src/App.py", "src/app.py"),
        ("caf\u00e9.py", "cafe\u0301.py"),
        ("src/a//b.py", "src/a/b.py"),
        ("src/a/./b.py", "src/a/b.py"),
    ],
)
def test_rejects_duplicate_normalized_names(tmp_path: Path, names: tuple[str, str]) -> None:
    archive = make_zip(
        tmp_path / "payload.zip",
        [(names[0], b"one"), (names[1], b"two")],
    )

    with pytest.raises(UnsafeArchiveError, match="duplicate_path"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())


def test_rejects_file_directory_prefix_collision(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "payload.zip",
        [("src", b"file"), ("src/app.py", b"nested")],
    )

    with pytest.raises(UnsafeArchiveError, match="path_collision"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())


def test_rejects_unix_symlink(tmp_path: Path) -> None:
    link = ZipInfo("linked.py")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive = make_zip(tmp_path / "payload.zip", [(link, b"outside.py")])

    with pytest.raises(UnsafeArchiveError, match="link_entry"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())


def test_rejects_encrypted_entry(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "payload.zip", [("app.py", b"safe")])
    payload = bytearray(archive.read_bytes())
    local = payload.index(b"PK\x03\x04")
    central = payload.index(b"PK\x01\x02")
    payload[local + 6 : local + 8] = (1).to_bytes(2, "little")
    payload[central + 8 : central + 10] = (1).to_bytes(2, "little")
    archive.write_bytes(payload)

    with pytest.raises(UnsafeArchiveError, match="encrypted_entry"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())


def test_rejects_archive_over_file_count_limit(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "payload.zip",
        [(f"{index}.py", b"safe") for index in range(3)],
    )

    with pytest.raises(UnsafeArchiveError, match="too_many_files"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits(max_files=2))


def test_rejects_declared_expansion_over_byte_limit(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "payload.zip", [("large.py", b"x" * 11)])

    with pytest.raises(UnsafeArchiveError, match="archive_too_large"):
        extract_zip_safely(
            archive,
            tmp_path / "out",
            ArchiveLimits(max_extracted_bytes=10),
        )


def test_rejects_paths_over_depth_limit(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "payload.zip", [("a/b/c/app.py", b"safe")])

    with pytest.raises(UnsafeArchiveError, match="path_too_long"):
        extract_zip_safely(
            archive,
            tmp_path / "out",
            ArchiveLimits(max_path_depth=3),
        )


def test_rejects_unsupported_compression(tmp_path: Path) -> None:
    archive_path = tmp_path / "payload.zip"
    with ZipFile(archive_path, "w", compression=ZIP_BZIP2) as archive:
        archive.writestr("app.py", b"safe")

    with pytest.raises(UnsafeArchiveError, match="unsupported_compression"):
        extract_zip_safely(archive_path, tmp_path / "out", ArchiveLimits())


def test_existing_destination_is_preserved(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "payload.zip", [("app.py", b"new")])
    destination = tmp_path / "out"
    destination.write_text("keep", encoding="utf-8")

    with pytest.raises(UnsafeArchiveError, match="destination_exists"):
        extract_zip_safely(archive, destination, ArchiveLimits())

    assert destination.read_text(encoding="utf-8") == "keep"


def test_extracts_valid_files_in_stable_order(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "payload.zip",
        [("z.py", b"z = 1"), ("src/a.py", b"a = 1"), ("src/", b"")],
    )
    destination = tmp_path / "out"

    extracted = extract_zip_safely(archive, destination, ArchiveLimits())

    assert [path.relative_to(destination).as_posix() for path in extracted] == [
        "src/a.py",
        "z.py",
    ]
    assert (destination / "src" / "a.py").read_bytes() == b"a = 1"
