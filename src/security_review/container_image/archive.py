"""Verify one trusted Docker-save tar without extracting files to disk."""

from __future__ import annotations

import gzip
import json
import re
import tarfile
import zlib
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import IO, Any

from security_review.container_image.errors import ImageScanError

MAX_TAR_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_METADATA_BYTES = 1024 * 1024
MAX_UNCOMPRESSED_LAYER_BYTES = 2 * 1024 * 1024 * 1024
MAX_UNCOMPRESSED_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_DIFF_ID_SECONDS = 120.0
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
_BLOB = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")
_LEGACY_CONFIG = re.compile(r"([0-9a-f]{64})\.json\Z")
_OCI_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_GZIP_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
_TAR_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
}


@dataclass(frozen=True)
class ImageTarIdentity:
    """Separate transport, local Docker, and runtime image-config identities."""

    tar_sha256: str
    local_id: str
    config_digest: str


def _valid_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and bool(path.parts)
        and not path.is_absolute()
        and "\\" not in name
        and ".." not in path.parts
        and ":" not in path.parts[0]
        and all(ord(character) >= 32 and ord(character) != 127 for character in name)
    )


def _hash_stream(handle: IO[bytes]) -> str:
    digest = sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _tar_hash(path: Path) -> str:
    with path.open("rb") as handle:
        return _hash_stream(handle)


def _get_file(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str
) -> IO[bytes]:
    member = members.get(name)
    if member is None or not member.isfile():
        raise ImageScanError("image_archive_missing_blob")
    handle = archive.extractfile(member)
    if handle is None:
        raise ImageScanError("image_archive_missing_blob")
    return handle


def _small_json(archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo], name: str) -> Any:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > MAX_METADATA_BYTES:
        raise ImageScanError("image_archive_invalid_metadata")
    with _get_file(archive, members, name) as handle:
        raw = handle.read(MAX_METADATA_BYTES + 1)
    if len(raw) != member.size or len(raw) > MAX_METADATA_BYTES:
        raise ImageScanError("image_archive_invalid_metadata")
    try:
        return json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise ImageScanError("image_archive_invalid_metadata") from error


def _hex_digest(value: object) -> str:
    if not isinstance(value, str) or (match := _DIGEST.fullmatch(value)) is None:
        raise ImageScanError("image_archive_invalid_digest")
    return match.group(1)


def _verified_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    digest: object,
    size: object,
) -> str:
    hash_hex = _hex_digest(digest)
    name = f"blobs/sha256/{hash_hex}"
    member = members.get(name)
    if member is None or not member.isfile() or type(size) is not int or size < 0:
        raise ImageScanError("image_archive_invalid_blob")
    if member.size != size:
        raise ImageScanError("image_archive_invalid_blob")
    with _get_file(archive, members, name) as handle:
        if _hash_stream(handle) != hash_hex:
            raise ImageScanError("image_archive_invalid_blob")
    return name


def _config_identity(config: object) -> str:
    if not isinstance(config, dict):
        raise ImageScanError("image_archive_invalid_config")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ImageScanError("image_archive_wrong_platform")
    return "linux/amd64"


def _inspect_oci(
    archive: tarfile.TarFile, members: dict[str, tarfile.TarInfo]
) -> tuple[str, str, list[tuple[str, str]], dict[str, Any]]:
    index = _small_json(archive, members, "index.json")
    if not isinstance(index, dict) or index.get("schemaVersion") != 2:
        raise ImageScanError("image_archive_invalid_index")
    descriptors = index.get("manifests")
    if not isinstance(descriptors, list) or len(descriptors) != 1:
        raise ImageScanError("image_archive_ambiguous_manifest")
    descriptor = descriptors[0]
    if not isinstance(descriptor, dict) or descriptor.get("mediaType") not in _OCI_MANIFEST_TYPES:
        raise ImageScanError("image_archive_invalid_manifest")
    platform = descriptor.get("platform")
    # docker save of one local image may omit a platform descriptor. The
    # verified config blob remains the authoritative platform assertion.
    if platform is not None and (
        not isinstance(platform, dict)
        or platform.get("os") != "linux"
        or platform.get("architecture") != "amd64"
    ):
        raise ImageScanError("image_archive_wrong_platform")
    manifest_name = _verified_blob(
        archive, members, descriptor.get("digest"), descriptor.get("size")
    )
    manifest = _small_json(archive, members, manifest_name)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ImageScanError("image_archive_invalid_manifest")
    config_descriptor = manifest.get("config")
    if not isinstance(config_descriptor, dict):
        raise ImageScanError("image_archive_invalid_config")
    config_name = _verified_blob(
        archive, members, config_descriptor.get("digest"), config_descriptor.get("size")
    )
    config = _small_json(archive, members, config_name)
    _config_identity(config)
    if not isinstance(config, dict):
        raise ImageScanError("image_archive_invalid_config")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) > MAX_ARCHIVE_ENTRIES:
        raise ImageScanError("image_archive_invalid_layers")
    layer_entries: list[tuple[str, str]] = []
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get("mediaType"), str):
            raise ImageScanError("image_archive_invalid_layers")
        layer_entries.append(
            (
                _verified_blob(archive, members, layer.get("digest"), layer.get("size")),
                layer["mediaType"],
            )
        )
    return str(descriptor["digest"]), str(config_descriptor["digest"]), layer_entries, config


def _verify_oci_diff_ids(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    layers: list[tuple[str, str]],
    config: dict[str, Any],
) -> None:
    """Bind a config local ID to bounded, uncompressed OCI layer contents."""

    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        raise ImageScanError("image_archive_invalid_layers")
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
        raise ImageScanError("image_archive_invalid_layers")
    deadline = monotonic() + MAX_DIFF_ID_SECONDS
    total_bytes = 0
    for (name, media_type), expected in zip(layers, diff_ids, strict=True):
        expected_hex = _hex_digest(expected)
        if media_type not in _GZIP_LAYER_TYPES | _TAR_LAYER_TYPES:
            raise ImageScanError("image_archive_invalid_layers")
        if media_type in _TAR_LAYER_TYPES and members[name].size > MAX_UNCOMPRESSED_LAYER_BYTES:
            raise ImageScanError("image_archive_invalid_layers")
        layer_bytes = 0
        digest = sha256()
        try:
            with _get_file(archive, members, name) as handle:
                source = (
                    gzip.GzipFile(fileobj=handle, mode="rb")
                    if media_type in _GZIP_LAYER_TYPES
                    else handle
                )
                with source:
                    while True:
                        if monotonic() >= deadline:
                            raise ImageScanError("image_archive_invalid_layers")
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        layer_bytes += len(chunk)
                        total_bytes += len(chunk)
                        if (
                            layer_bytes > MAX_UNCOMPRESSED_LAYER_BYTES
                            or total_bytes > MAX_UNCOMPRESSED_TOTAL_BYTES
                        ):
                            raise ImageScanError("image_archive_invalid_layers")
                        digest.update(chunk)
        except (OSError, EOFError, zlib.error) as error:
            raise ImageScanError("image_archive_invalid_layers") from error
        if digest.hexdigest() != expected_hex:
            raise ImageScanError("image_archive_invalid_layers")


def _inspect_legacy(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    *,
    verify_diff_ids: bool,
) -> tuple[str, list[str]]:
    manifest = _small_json(archive, members, "manifest.json")
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        raise ImageScanError("image_archive_ambiguous_manifest")
    entry = manifest[0]
    config_name = entry.get("Config")
    if not isinstance(config_name, str):
        raise ImageScanError("image_archive_invalid_config")
    match = _BLOB.fullmatch(config_name) or _LEGACY_CONFIG.fullmatch(config_name)
    if match is None:
        raise ImageScanError("image_archive_invalid_config")
    config_digest = f"sha256:{match.group(1)}"
    config = _small_json(archive, members, config_name)
    with _get_file(archive, members, config_name) as handle:
        if _hash_stream(handle) != match.group(1):
            raise ImageScanError("image_archive_invalid_config")
    _config_identity(config)
    layers = entry.get("Layers")
    if not isinstance(layers, list) or len(layers) > MAX_ARCHIVE_ENTRIES:
        raise ImageScanError("image_archive_invalid_layers")
    for name in layers:
        if (
            not isinstance(name, str)
            or not _valid_archive_name(name)
            or name not in members
            or not members[name].isfile()
        ):
            raise ImageScanError("image_archive_invalid_layers")
    if verify_diff_ids:
        # Legacy Docker save layers are uncompressed layer.tar streams. The
        # config rootfs binds their ordered SHA-256 diff IDs to the local ID.
        rootfs = config.get("rootfs") if isinstance(config, dict) else None
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
        if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
            raise ImageScanError("image_archive_invalid_layers")
        for name, expected in zip(layers, diff_ids, strict=True):
            digest = _hex_digest(expected)
            with _get_file(archive, members, name) as handle:
                if _hash_stream(handle) != digest:
                    raise ImageScanError("image_archive_invalid_layers")
    return config_digest, layers


def inspect_image_tar(path: Path, *, expected_local_id: str) -> ImageTarIdentity:
    """Bind one saved tar to the build's exact local ID and runtime config."""

    _hex_digest(expected_local_id)
    try:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_TAR_BYTES:
            raise ImageScanError("image_archive_invalid_size")
        tar_sha256 = _tar_hash(path)
        with tarfile.open(path, mode="r:") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive:
                if len(members) >= MAX_ARCHIVE_ENTRIES or not _valid_archive_name(member.name):
                    raise ImageScanError("image_archive_invalid_entries")
                if member.name in members or not (member.isfile() or member.isdir()):
                    raise ImageScanError("image_archive_invalid_entries")
                members[member.name] = member
            if "manifest.json" not in members:
                raise ImageScanError("image_archive_missing_manifest")
            legacy_config, legacy_layers = _inspect_legacy(
                archive, members, verify_diff_ids="index.json" not in members
            )
            valid_ids = {legacy_config}
            if "index.json" in members:
                manifest_id, oci_config, oci_layers, oci_config_data = _inspect_oci(
                    archive, members
                )
                if oci_config != legacy_config or [name for name, _ in oci_layers] != legacy_layers:
                    raise ImageScanError("image_archive_identity_mismatch")
                with _get_file(archive, members, "index.json") as handle:
                    index_id = f"sha256:{_hash_stream(handle)}"
                valid_ids = {manifest_id, index_id}
                if expected_local_id == oci_config:
                    # Docker's classic store can report a config digest as
                    # the local ID even when docker save emits an OCI index.
                    _verify_oci_diff_ids(archive, members, oci_layers, oci_config_data)
                    valid_ids.add(oci_config)
            if expected_local_id not in valid_ids:
                raise ImageScanError("image_archive_identity_mismatch")
        return ImageTarIdentity(tar_sha256, expected_local_id, legacy_config)
    except ImageScanError:
        raise
    except (OSError, tarfile.TarError, ValueError) as error:
        raise ImageScanError("image_archive_unreadable") from error
