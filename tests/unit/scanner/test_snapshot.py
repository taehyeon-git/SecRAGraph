from pathlib import Path

import pytest

from security_review.scanner.files import ScanLimits, discover_files
from security_review.scanner.snapshot import safe_snapshot


def test_snapshot_copies_only_accepted_files_and_omits_target_configs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (source / ".semgrep.yml").write_text("rules: []\n", encoding="utf-8")
    (source / ".checkov.yaml").write_text("external-checks-dir: .\n", encoding="utf-8")
    (source / ".gitleaks.toml").write_text("[extend]\nuseDefault = false\n", encoding="utf-8")
    (source / ".gitleaksignore").write_text("*\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    link_available = True
    try:
        (source / "linked.py").symlink_to(outside)
    except OSError:
        link_available = False

    discovery = discover_files(source, ScanLimits())
    with safe_snapshot(discovery, ScanLimits()) as snapshot:
        assert snapshot.paths == ("app.py",)
        assert (snapshot.root / "app.py").read_text(encoding="utf-8") == "print('ok')\n"
        assert not (snapshot.root / ".gitleaksignore").exists()
        if link_available:
            assert not (snapshot.root / "linked.py").exists()
        root = snapshot.root
    assert not root.exists()


def test_snapshot_marks_changed_files_unreadable(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    discovery = discover_files(source, ScanLimits())
    source.unlink()
    with safe_snapshot(discovery, ScanLimits()) as snapshot:
        assert snapshot.paths == ()
        assert snapshot.skipped == (("app.py", "file_changed_or_unreadable"),)


def test_snapshot_rejects_same_size_changed_file(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("safe = 1\n", encoding="utf-8")
    discovery = discover_files(source, ScanLimits())
    source.write_text("evil = 1\n", encoding="utf-8")

    with safe_snapshot(discovery, ScanLimits()) as snapshot:
        assert snapshot.paths == ()
        assert snapshot.skipped == (("app.py", "file_changed_or_unreadable"),)


def test_snapshot_does_not_copy_more_than_aggregate_limit(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a" * 8, encoding="utf-8")
    (tmp_path / "b.py").write_text("b" * 8, encoding="utf-8")
    limits = ScanLimits(max_file_bytes=10, max_total_bytes=12)
    discovery = discover_files(tmp_path, limits)
    with safe_snapshot(discovery, limits) as snapshot:
        assert snapshot.paths == ("a.py",)
        assert snapshot.skipped == (("b.py", "aggregate_limit_exceeded"),)


def test_snapshot_uses_separate_nonexecutable_staging_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setenv("SECRAGRAPH_SNAPSHOT_TMPDIR", str(staging))

    with safe_snapshot(discover_files(source, ScanLimits()), ScanLimits()) as snapshot:
        assert snapshot.root.parent == staging
        assert snapshot.paths == ("app.py",)
