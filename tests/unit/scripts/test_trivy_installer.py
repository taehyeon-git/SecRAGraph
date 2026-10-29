"""Pinned Trivy installation tests without network access."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from infra.scanners.install_trivy import install, verified_trivy_asset


def _archive(name: str = "trivy", payload: bytes = b"fake-trivy") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_asset_digest_is_required() -> None:
    archive = _archive()
    with patch(
        "infra.scanners.install_trivy.urllib.request.urlopen", return_value=_Response(archive)
    ):
        with pytest.raises(ValueError, match="digest"):
            verified_trivy_asset(expected_sha256="0" * 64)
    with patch(
        "infra.scanners.install_trivy.urllib.request.urlopen", return_value=_Response(archive)
    ):
        assert verified_trivy_asset(expected_sha256=hashlib.sha256(archive).hexdigest()) == archive


def test_installer_reads_only_expected_root_member(tmp_path: Path) -> None:
    archive = _archive("../trivy")
    with patch("infra.scanners.install_trivy.verified_trivy_asset", return_value=archive):
        with pytest.raises(ValueError, match="binary"):
            install(tmp_path)
    assert not (tmp_path / "trivy").exists()


def test_installer_writes_verified_executable(tmp_path: Path) -> None:
    archive = _archive()
    with patch("infra.scanners.install_trivy.verified_trivy_asset", return_value=archive):
        result = install(tmp_path)
    assert result == tmp_path / "trivy"
    assert result.read_bytes() == b"fake-trivy"
