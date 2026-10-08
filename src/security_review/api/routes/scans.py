"""Secure synchronous scan endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, UploadFile

from security_review.api.dependencies import (
    TempDirectoryFactory,
    get_scan_service,
    get_settings,
    get_temp_factory,
)
from security_review.api.errors import APIError
from security_review.api.schemas import ScanReport
from security_review.application import ScanService
from security_review.config import Settings
from security_review.uploads import (
    FILE_UPLOAD_POLICY,
    ZIP_UPLOAD_POLICY,
    ArchiveLimits,
    UnsafeArchiveError,
    UploadError,
    extract_zip_safely,
    save_upload,
    validate_upload_metadata,
)

router = APIRouter(prefix="/v1/scans", tags=["scans"])


def _upload_api_error(error: UploadError) -> APIError:
    if error.code == "upload_too_large":
        return APIError(413, error.code, "The uploaded file exceeds the configured limit.")
    if error.code == "unsupported_media_type":
        return APIError(415, error.code, "The uploaded file type is not supported.")
    messages = {
        "destination_exists": "The upload could not be stored safely.",
        "empty_filename": "A non-empty filename is required.",
        "unsafe_filename": "The supplied filename is not safe.",
        "upload_read_failed": "The uploaded file could not be read.",
    }
    return APIError(422, error.code, messages.get(error.code, "The upload is invalid."))


def _save(
    file: UploadFile | str,
    root: Path,
    settings: Settings,
    *,
    archive: bool,
) -> tuple[Path, str]:
    if isinstance(file, str):
        raise UploadError("empty_filename")
    policy = ZIP_UPLOAD_POLICY if archive else FILE_UPLOAD_POLICY
    name = validate_upload_metadata(file.filename, file.content_type, policy)
    target = save_upload(file.file, root / name, settings.max_upload_bytes)
    return target, name


@router.post("/file", response_model=ScanReport)
def scan_file_upload(
    file: Annotated[UploadFile | str, File()],
    service: Annotated[ScanService, Depends(get_scan_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    temp_factory: Annotated[TempDirectoryFactory, Depends(get_temp_factory)],
) -> ScanReport:
    """Scan one supported source file without executing it."""

    try:
        with temp_factory() as directory:
            target, name = _save(file, Path(directory), settings, archive=False)
            return service.scan(target, target_name=name)
    except UploadError as error:
        raise _upload_api_error(error) from error


@router.post("/archive", response_model=ScanReport)
def scan_archive_upload(
    file: Annotated[UploadFile | str, File()],
    service: Annotated[ScanService, Depends(get_scan_service)],
    settings: Annotated[Settings, Depends(get_settings)],
    temp_factory: Annotated[TempDirectoryFactory, Depends(get_temp_factory)],
) -> ScanReport:
    """Safely extract and scan one ZIP archive without executing its contents."""

    try:
        with temp_factory() as directory:
            root = Path(directory)
            archive, name = _save(file, root, settings, archive=True)
            extracted = root / "extracted"
            extract_zip_safely(
                archive,
                extracted,
                ArchiveLimits(
                    max_files=settings.max_archive_files,
                    max_extracted_bytes=settings.max_extracted_bytes,
                ),
            )
            return service.scan(extracted, target_name=name)
    except UploadError as error:
        raise _upload_api_error(error) from error
    except UnsafeArchiveError as error:
        raise APIError(422, "unsafe_archive", "The ZIP archive is invalid or unsafe.") from error
