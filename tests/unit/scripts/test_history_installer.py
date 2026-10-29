"""The CI history gate installs only the pinned Gitleaks binary."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from infra.scanners import install_tools


def _fake_gitleaks_archive() -> bytes:
    payload = b"verified-gitleaks-test-binary"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("gitleaks")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def test_gitleaks_only_installer_never_downloads_opengrep(tmp_path: Path, monkeypatch) -> None:
    requested: list[str] = []
    archive = _fake_gitleaks_archive()

    def download(url: str, _digest: str) -> bytes:
        requested.append(url)
        return archive

    monkeypatch.setattr(install_tools, "_verified_download", download)

    install_tools.install_gitleaks(tmp_path, "amd64")

    assert (tmp_path / "gitleaks").read_bytes() == b"verified-gitleaks-test-binary"
    assert not (tmp_path / "opengrep").exists()
    assert len(requested) == 1
    assert "gitleaks_8.30.1_linux_x64.tar.gz" in requested[0]


def test_existing_install_still_installs_both_tools(tmp_path: Path, monkeypatch) -> None:
    requested: list[str] = []
    archive = _fake_gitleaks_archive()

    def download(url: str, _digest: str) -> bytes:
        requested.append(url)
        return archive if "gitleaks" in url else b"verified-opengrep-test-binary"

    monkeypatch.setattr(install_tools, "_verified_download", download)

    install_tools.install(tmp_path, "amd64")

    assert (tmp_path / "opengrep").read_bytes() == b"verified-opengrep-test-binary"
    assert (tmp_path / "gitleaks").read_bytes() == b"verified-gitleaks-test-binary"
    assert len(requested) == 2


def test_cli_gitleaks_only_dispatches_without_default_install(tmp_path: Path, monkeypatch) -> None:
    requested: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        install_tools,
        "install_gitleaks",
        lambda destination, architecture: requested.append((destination, architecture)),
        raising=False,
    )
    monkeypatch.setattr(
        install_tools,
        "install",
        lambda *_args: (_ for _ in ()).throw(AssertionError("default installer ran")),
    )

    assert install_tools.main([str(tmp_path), "amd64", "--gitleaks-only"]) == 0
    assert requested == [(tmp_path, "amd64")]
