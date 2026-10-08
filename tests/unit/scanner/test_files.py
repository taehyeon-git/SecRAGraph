from pathlib import Path

import pytest

from security_review.scanner.files import ScanLimits, discover_files, read_scannable_text


def test_binary_file_is_reported_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_bytes(b"print('ok')\x00\xff")

    result = discover_files(target, ScanLimits())

    assert result.files == ()
    assert [(item.path, item.reason) for item in result.skipped] == [
        ("payload.py", "binary_or_invalid_utf8")
    ]


def test_invalid_utf8_file_is_reported_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_bytes(b"print('ok')\xff")

    result = discover_files(target, ScanLimits())

    assert result.files == ()
    assert result.skipped[0].reason == "binary_or_invalid_utf8"


def test_symlink_outside_root_is_not_scanned(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("password='outside'", encoding="utf-8")
    link = root / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    result = discover_files(root, ScanLimits())

    assert result.files == ()
    assert [(item.path, item.reason) for item in result.skipped] == [("linked.py", "symlink")]


def test_unsupported_extension_is_reported_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("not scanned", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits())

    assert result.files == ()
    assert result.skipped[0].reason == "unsupported_extension"


def test_file_larger_than_limit_is_reported_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "large.py"
    target.write_text("x" * 11, encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits(max_file_bytes=10))

    assert result.files == ()
    assert result.skipped[0].reason == "file_too_large"


def test_file_exactly_at_byte_limit_is_accepted(tmp_path: Path) -> None:
    target = tmp_path / "exact.py"
    target.write_bytes(b"x" * 10)

    result = discover_files(tmp_path, ScanLimits(max_file_bytes=10))

    assert [item.relative_path for item in result.files] == ["exact.py"]


def test_discovery_sorts_relative_paths_deterministically(tmp_path: Path) -> None:
    (tmp_path / "z.py").write_text("z = 1", encoding="utf-8")
    nested = tmp_path / "a"
    nested.mkdir()
    (nested / "b.py").write_text("b = 1", encoding="utf-8")
    (nested / "a.py").write_text("a = 1", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits())

    assert [item.relative_path for item in result.files] == ["a/a.py", "a/b.py", "z.py"]


def test_max_files_is_enforced_after_deterministic_sort(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_text(f"name = '{name}'", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits(max_files=2))

    assert [item.relative_path for item in result.files] == ["a.py", "b.py"]
    assert [(item.path, item.reason) for item in result.skipped] == [("c.py", "max_files_exceeded")]


def test_single_file_uses_only_its_name_and_can_be_read(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('safe')", encoding="utf-8")

    result = discover_files(target, ScanLimits())

    assert len(result.files) == 1
    assert result.files[0].relative_path == "app.py"
    assert read_scannable_text(result.files[0], ScanLimits()) == "print('safe')"


def test_dotenv_is_a_supported_source_file(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("DEMO=true", encoding="utf-8")

    result = discover_files(target, ScanLimits())

    assert [item.relative_path for item in result.files] == [".env"]


def test_extension_matching_is_case_insensitive(tmp_path: Path) -> None:
    target = tmp_path / "APP.PY"
    target.write_text("message = '안전'", encoding="utf-8")

    result = discover_files(target, ScanLimits())

    assert read_scannable_text(result.files[0], ScanLimits()) == "message = '안전'"


def test_read_rechecks_size_after_discovery(tmp_path: Path) -> None:
    target = tmp_path / "changing.py"
    target.write_text("small", encoding="utf-8")
    limits = ScanLimits(max_file_bytes=10)
    discovered = discover_files(target, limits).files[0]
    target.write_text("x" * 11, encoding="utf-8")

    assert read_scannable_text(discovered, limits) is None


@pytest.mark.parametrize(
    "limits",
    [
        {"max_file_bytes": 0},
        {"max_files": 0},
        {"max_candidates": 0},
        {"max_processing_seconds": 0},
    ],
)
def test_scan_limits_require_positive_bounds(limits: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="positive"):
        ScanLimits(**limits)  # type: ignore[arg-type]


def test_dependency_and_vcs_directories_are_excluded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("safe = True", encoding="utf-8")
    for directory in (".git", ".venv", "node_modules"):
        ignored = tmp_path / directory
        ignored.mkdir()
        (ignored / "ignored.py").write_text("eval(user_input)", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits())

    assert [item.relative_path for item in result.files] == ["app.py"]


def test_discovery_stops_at_candidate_limit(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"{index}.py").write_text("safe = True", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits(max_candidates=2))

    assert result.warnings == ("candidate_limit_exceeded",)
    assert len(result.files) <= 2


def test_candidate_limit_does_not_warn_when_exactly_satisfied(tmp_path: Path) -> None:
    for index in range(2):
        (tmp_path / f"{index}.py").write_text("safe = True", encoding="utf-8")

    result = discover_files(tmp_path, ScanLimits(max_candidates=2))

    assert result.warnings == ()
    assert len(result.files) == 2


def test_discovery_stops_when_deadline_expires(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("safe = True", encoding="utf-8")
    (tmp_path / "b.py").write_text("safe = True", encoding="utf-8")
    ticks = iter((0.0, 0.0, 2.0))

    result = discover_files(
        tmp_path,
        ScanLimits(),
        deadline=1.0,
        clock=lambda: next(ticks, 2.0),
    )

    assert result.warnings == ("processing_time_limit_exceeded",)
