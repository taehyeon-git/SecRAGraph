from __future__ import annotations

from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory, gettempdir
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_review.api.app import create_app
from security_review.api.dependencies import get_scan_service, get_temp_factory
from security_review.config import Settings
from security_review.domain.models import Confidence, Finding, Severity, SourceReference
from security_review.scanner.files import ScanLimits


class RaisingScanService:
    def scan(self, target: Path, *, target_name: str) -> None:
        del target, target_name
        raise RuntimeError("scanner failure must stay private")


class RecordingTempFactory:
    def __init__(self, root: Path) -> None:
        self._root = root
        self.created: list[Path] = []

    def __call__(self) -> TemporaryDirectory[str]:
        directory = TemporaryDirectory(prefix="secragraph-test-", dir=self._root)
        self.created.append(Path(directory.name))
        return directory


def zip_payload(entries: dict[str, bytes]) -> bytes:
    payload = BytesIO()
    with ZipFile(payload, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return payload.getvalue()


@pytest.fixture
def app() -> FastAPI:
    return create_app(Settings(testing=True))


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def test_file_scan_returns_redacted_report(client: TestClient) -> None:
    token = "sk-test-1234567890abcdef"

    response = client.post(
        "/v1/scans/file",
        files={"file": ("settings.py", f'OPENAI_API_KEY="{token}"\n', "text/x-python")},
    )

    assert response.status_code == 200
    assert response.json()["target_name"] == "settings.py"
    assert response.json()["findings"][0]["rule_id"] == "SEC001"
    assert token not in response.text


def test_archive_scan_preserves_original_name_and_relative_paths(client: TestClient) -> None:
    response = client.post(
        "/v1/scans/archive",
        files={
            "file": (
                "backend-source.zip",
                zip_payload({"src/app.py": b"eval(user_input)\n"}),
                "application/zip",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["target_name"] == "backend-source.zip"
    assert body["findings"][0]["file_path"] == "src/app.py"


def test_archive_scan_uses_automatic_dependency_auditor() -> None:
    calls: list[str] = []
    dependency_finding = Finding(
        id="OSV001:sample",
        rule_id="OSV001",
        category="dependency",
        severity=Severity.INFO,
        file_path="package-lock.json",
        line_start=1,
        message="Locked package matched an OSV advisory.",
        redacted_evidence="Version scoped OSV match; source omitted.",
        confidence=Confidence.HIGH,
        remediation="Upgrade to a reviewed fixed version.",
    )

    def auditor(target: Path, _limits: ScanLimits) -> SimpleNamespace:
        calls.append(target.name)
        return SimpleNamespace(findings=(dependency_finding,), warnings=())

    app = create_app(Settings(testing=True), dependency_auditor=auditor)
    response = TestClient(app).post(
        "/v1/scans/archive",
        files={
            "file": (
                "source.zip",
                zip_payload({"package-lock.json": b'{"lockfileVersion": 3, "packages": {}}'}),
                "application/zip",
            )
        },
    )

    assert response.status_code == 200
    assert calls
    assert response.json()["findings"][0]["rule_id"] == "OSV001"


def test_file_upload_accepts_exact_uv_lock_for_automatic_dependency_audit() -> None:
    seen: list[str] = []

    def auditor(target: Path, _limits: ScanLimits) -> SimpleNamespace:
        seen.append(target.name)
        return SimpleNamespace(findings=(), warnings=("dependency_lockfile_invalid",))

    app = create_app(Settings(testing=True), dependency_auditor=auditor)
    response = TestClient(app).post(
        "/v1/scans/file", files={"file": ("uv.lock", b"not toml", "text/plain")}
    )

    assert response.status_code == 200
    assert seen == ["uv.lock"]
    assert "dependency_lockfile_invalid" in response.json()["warnings"]


def test_api_can_disable_automatic_osv_lookup() -> None:
    def forbidden_auditor(_target: Path, _limits: ScanLimits) -> SimpleNamespace:
        pytest.fail("disabled API must not call OSV auditor")

    app = create_app(
        Settings(testing=True, auto_osv_enabled=False), dependency_auditor=forbidden_auditor
    )
    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("safe.py", b"answer = 42\n", "text/x-python")},
    )

    assert response.status_code == 200
    assert response.json()["summary"]["total"] == 0


def test_api_scan_prepares_official_cwe_for_detected_finding() -> None:
    seen: list[tuple[str, ...]] = []
    reference = SourceReference(
        id="mitre:CWE-95",
        title="CWE-95",
        source_url="https://cwe-api.mitre.org/api/v1/cwe/weakness/95",
    )

    def ensure(ids: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        seen.append(ids)
        return SimpleNamespace(references_by_id={"CWE-95": reference}, warnings=())

    app = create_app(Settings(testing=True), cwe_evidence=SimpleNamespace(ensure=ensure))
    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )

    assert response.status_code == 200
    assert seen == [("CWE-95",)]
    assert any(
        item["source_url"] == reference.source_url
        for item in response.json()["findings"][0]["references"]
    )


def test_api_setting_disables_automatic_cwe_evidence() -> None:
    def forbidden(_ids: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        pytest.fail("disabled API must not request official CWE evidence")

    app = create_app(
        Settings(testing=True, auto_cwe_enabled=False),
        cwe_evidence=SimpleNamespace(ensure=forbidden),
    )
    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )

    assert response.status_code == 200
    assert response.json()["findings"][0]["rule_id"] == "PY001"


@pytest.mark.parametrize(
    ("filename", "content_type", "expected_status", "expected_code"),
    [
        ("", "text/x-python", 422, "empty_filename"),
        ("notes.txt", "text/plain", 415, "unsupported_media_type"),
        ("app.py", "application/zip", 415, "unsupported_media_type"),
    ],
)
def test_file_endpoint_rejects_invalid_metadata(
    client: TestClient,
    filename: str,
    content_type: str,
    expected_status: int,
    expected_code: str,
) -> None:
    response = client.post(
        "/v1/scans/file",
        files={"file": (filename, b"print('safe')\n", content_type)},
    )

    assert response.status_code == expected_status
    assert response.json()["code"] == expected_code


def test_archive_endpoint_rejects_wrong_media_type(client: TestClient) -> None:
    response = client.post(
        "/v1/scans/archive",
        files={"file": ("source.zip", b"not-a-zip", "text/plain")},
    )

    assert response.status_code == 415
    assert response.json()["code"] == "unsupported_media_type"


def test_oversized_upload_returns_413_without_echoing_content() -> None:
    app = create_app(Settings(testing=True, max_upload_bytes=10))
    marker = "private-upload-content"

    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("app.py", marker.encode(), "text/x-python")},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "upload_too_large"
    assert marker not in response.text


def test_request_body_limit_rejects_before_multipart_processing() -> None:
    app = create_app(Settings(testing=True, max_upload_bytes=10_000, max_request_bytes=256))
    marker = "request-body-marker-" * 100

    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("app.py", marker.encode(), "text/x-python")},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "request_too_large"
    assert marker not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        b"not-a-zip",
        zip_payload({"../escape.py": b"print('unsafe')\n"}),
    ],
)
def test_archive_rejection_is_typed_and_does_not_echo_member_names(
    client: TestClient,
    payload: bytes,
) -> None:
    response = client.post(
        "/v1/scans/archive",
        files={"file": ("source.zip", payload, "application/zip")},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "unsafe_archive"
    assert "escape.py" not in response.text


def test_temporary_directory_is_removed_when_scanner_fails(
    app: FastAPI,
    tmp_path: Path,
) -> None:
    recording_factory = RecordingTempFactory(tmp_path)
    app.dependency_overrides[get_scan_service] = lambda: RaisingScanService()
    app.dependency_overrides[get_temp_factory] = lambda: recording_factory

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/scans/file",
        files={"file": ("app.py", b"print('x')\n", "text/x-python")},
    )

    assert response.status_code == 500
    assert recording_factory.created
    assert all(not path.exists() for path in recording_factory.created)
    assert "scanner failure" not in response.text


def test_temporary_directory_is_removed_when_archive_is_rejected(
    app: FastAPI,
) -> None:
    recording_factory = RecordingTempFactory(Path(gettempdir()))
    app.dependency_overrides[get_temp_factory] = lambda: recording_factory

    response = TestClient(app).post(
        "/v1/scans/archive",
        files={"file": ("source.zip", b"not-a-zip", "application/zip")},
    )

    assert response.status_code == 422
    assert recording_factory.created
    assert all(not path.exists() for path in recording_factory.created)
