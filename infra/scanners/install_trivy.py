"""Install the SHA-256-verified Trivy binary used by image CI."""

from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import urllib.request
from pathlib import Path
from tempfile import NamedTemporaryFile

VERSION = "0.76.1"
ASSET_URL = (
    "https://github.com/aquasecurity/trivy/releases/download/v0.76.1/"
    "trivy_0.76.1_Linux-64bit.tar.gz"
)
ASSET_SHA256 = "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
MAX_ASSET_BYTES = 150_000_000
MAX_BINARY_BYTES = 200_000_000


def verified_trivy_asset(*, expected_sha256: str = ASSET_SHA256) -> bytes:
    """Download a fixed official release asset and verify before parsing."""

    if not ASSET_URL.startswith("https://github.com/aquasecurity/trivy/releases/download/"):
        raise ValueError("unexpected Trivy download origin")
    with urllib.request.urlopen(ASSET_URL, timeout=60) as response:  # noqa: S310
        archive = bytes(response.read(MAX_ASSET_BYTES + 1))
    if len(archive) > MAX_ASSET_BYTES:
        raise ValueError("Trivy asset exceeds size limit")
    if hashlib.sha256(archive).hexdigest() != expected_sha256:
        raise ValueError("Trivy asset digest mismatch")
    return archive


def install(destination: Path) -> Path:
    """Copy only the root binary out of the verified archive, atomically."""

    archive = verified_trivy_asset()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        members = [member for member in source if member.name in {"trivy", "./trivy"}]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("verified Trivy archive has no unique root binary")
        member = members[0]
        if not 0 < member.size <= MAX_BINARY_BYTES:
            raise ValueError("verified Trivy binary exceeds size limit")
        stream = source.extractfile(member)
        if stream is None:
            raise ValueError("verified Trivy binary is missing")
        with stream:
            binary = stream.read(MAX_BINARY_BYTES + 1)
        if len(binary) != member.size:
            raise ValueError("verified Trivy binary length mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "trivy"
    if target.is_symlink():
        raise ValueError("Trivy target must not be a symlink")
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(prefix=".trivy-", dir=destination, delete=False) as output:
            output.write(binary)
            temporary = Path(output.name)
        temporary.chmod(0o755)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def main(arguments: list[str] | None = None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    if len(args) != 1:
        raise SystemExit("usage: python -m infra.scanners.install_trivy OUTPUT_DIRECTORY")
    install(Path(args[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
