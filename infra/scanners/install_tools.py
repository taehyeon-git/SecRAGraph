"""Install verified, fixed upstream scanner binaries into the runtime image."""

from __future__ import annotations

import hashlib
import io
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

_ASSETS = {
    "amd64": {
        "opengrep": (
            "https://github.com/opengrep/opengrep/releases/download/v1.32.0/opengrep_manylinux_x86",
            "7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75",
        ),
        "gitleaks": (
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        ),
    },
    "arm64": {
        "opengrep": (
            "https://github.com/opengrep/opengrep/releases/download/v1.32.0/opengrep_manylinux_aarch64",
            "dc6229319c0d68948733053786a5614873947e5ec1d4669cc0e94ae9038cb99d",
        ),
        "gitleaks": (
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
            "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        ),
    },
}
_MAX_ASSET_BYTES = 150_000_000


def _verified_download(url: str, digest: str) -> bytes:
    if not url.startswith("https://github.com/"):
        raise ValueError("unexpected scanner download host")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310  # nosec B310
        payload = response.read(_MAX_ASSET_BYTES + 1)
    if len(payload) > _MAX_ASSET_BYTES:
        raise ValueError("scanner asset too large")
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("scanner asset digest mismatch")
    return payload


def install(destination: Path, architecture: str) -> None:
    assets = _ASSETS.get(architecture)
    if assets is None:
        raise ValueError("unsupported scanner architecture")
    destination.mkdir(parents=True, exist_ok=True)
    opengrep = _verified_download(*assets["opengrep"])
    opengrep_path = destination / "opengrep"
    opengrep_path.write_bytes(opengrep)
    opengrep_path.chmod(0o755)

    install_gitleaks(destination, architecture)


def install_gitleaks(destination: Path, architecture: str) -> None:
    """Install only the SHA-verified Gitleaks asset for the history CI gate."""

    assets = _ASSETS.get(architecture)
    if assets is None:
        raise ValueError("unsupported scanner architecture")
    destination.mkdir(parents=True, exist_ok=True)

    archive = _verified_download(*assets["gitleaks"])
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        member = source.getmember("gitleaks")
        if not member.isfile() or not 0 < member.size <= 100_000_000:
            raise ValueError("invalid gitleaks archive")
        stream = source.extractfile(member)
        if stream is None:
            raise ValueError("missing gitleaks binary")
        with stream, (destination / "gitleaks").open("wb") as target:
            shutil.copyfileobj(stream, target)
    (destination / "gitleaks").chmod(0o755)


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    if len(args) == 2:
        install(Path(args[0]), args[1])
        return 0
    if len(args) == 3 and args[2] == "--gitleaks-only":
        install_gitleaks(Path(args[0]), args[1])
        return 0
    raise SystemExit("usage: install_tools.py OUTPUT_DIRECTORY ARCHITECTURE [--gitleaks-only]")


if __name__ == "__main__":
    raise SystemExit(main())
