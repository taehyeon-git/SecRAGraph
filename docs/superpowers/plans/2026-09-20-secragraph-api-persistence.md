# SecRAGraph API and Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the core scanner through a typed FastAPI API, safely accept file and ZIP uploads, persist canonical reports in PostgreSQL, and run the API and database through Docker Compose.

**Architecture:** FastAPI adapters call the existing application service and map domain errors to stable HTTP responses. Safe archive handling remains an infrastructure-free utility, while a SQLAlchemy repository persists complete reports transactionally behind a domain-facing protocol.

**Tech Stack:** FastAPI, Pydantic Settings, SQLAlchemy 2, Alembic, PostgreSQL, psycopg 3, Docker Compose, pytest, HTTPX

**Spec:** `docs/superpowers/specs/2026-09-20-sec-ragraph-design.md`

## Global Constraints

- Complete `2026-09-20-secragraph-core-scanner.md` first.
- Python 3.11 or later; dependencies and lockfile are managed with `uv`.
- API input supports one file or one ZIP archive; the API never clones a remote repository.
- Uploaded content is temporary, bounded, and deleted after the request.
- Target code is never executed, imported, compiled, or passed to a package manager.
- PostgreSQL is the default local persistence service and must be replaceable by Supabase through configuration.

## Review Focus

- ZIP traversal, absolute paths, links, normalized-name collisions, and excessive expansion must be rejected before extraction; Task 2 pins each class.
- A content-type or endpoint mismatch must produce a typed 415/422 response, not an internal error; Task 2 pins this behavior.
- PostgreSQL failure must fail readiness and must not leave a partially persisted report; Tasks 1 and 4 pin this behavior.
- Unknown scan IDs and unsupported report formats must return stable 404/422 error bodies; Task 5 pins this behavior.
- Temporary upload directories must be removed on success and scanner failure; Task 3 pins this behavior.

---

### Task 1: FastAPI foundation, configuration, and health contract

**Files:**
- Modify: `pyproject.toml`
- Create: `src/security_review/config.py`
- Create: `src/security_review/api/__init__.py`
- Create: `src/security_review/api/app.py`
- Create: `src/security_review/api/errors.py`
- Create: `src/security_review/api/routes/health.py`
- Create: `apps/__init__.py`
- Create: `apps/api/__init__.py`
- Create: `apps/api/main.py`
- Test: `tests/unit/api/test_health.py`
- Test: `tests/unit/api/test_errors.py`

**Interfaces:**
- Consumes: no persistence implementation yet; health uses an injected `ReadinessProbe` protocol.
- Produces: `Settings`, `create_app(settings: Settings | None = None) -> FastAPI`, `ReadinessProbe.check() -> Mapping[str, bool]`, and stable `ErrorResponse` bodies.

- [ ] **Step 1: Add API and database dependencies**

Run:

```bash
uv add fastapi pydantic-settings python-multipart "uvicorn[standard]" sqlalchemy alembic "psycopg[binary]"
uv add --dev httpx
```

Expected: dependencies are added to `pyproject.toml` and locked.

- [ ] **Step 2: Write failing liveness, readiness, and error-shape tests**

```python
def test_liveness_does_not_require_dependencies() -> None:
    client = TestClient(create_app(Settings(testing=True)))
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_is_503_when_postgres_is_down() -> None:
    app = create_app(Settings(testing=True))
    app.dependency_overrides[get_readiness_probe] = lambda: FakeProbe(
        {"postgres": False, "qdrant": True}
    )
    response = TestClient(app).get("/health/ready")
    assert response.status_code == 503
    assert response.json()["dependencies"]["postgres"] is False


def test_validation_error_has_stable_shape() -> None:
    response = TestClient(create_app(Settings(testing=True))).get("/v1/scans/not-a-uuid")
    assert response.status_code in {404, 422}
    body = response.json()
    assert set(body) >= {"code", "message", "correlation_id"}
```

Run: `uv run pytest tests/unit/api/test_health.py tests/unit/api/test_errors.py -v`
Expected: FAIL because the API package does not exist.

- [ ] **Step 3: Implement typed settings and the application factory**

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECRAGRAPH_", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    testing: bool = False
    database_url: str = "postgresql+psycopg://secragraph@postgres:5432/secragraph"
    qdrant_url: str = "http://qdrant:6333"
    max_upload_bytes: int = 5_000_000
    max_extracted_bytes: int = 20_000_000
    max_archive_files: int = 500
```

Build the FastAPI app with title `SecRAGraph`, versioned routers, a correlation-ID middleware, and exception handlers that return `ErrorResponse(code, message, correlation_id, details)` without stack traces.

Run: `uv run pytest tests/unit/api/test_health.py tests/unit/api/test_errors.py -v`
Expected: PASS.

- [ ] **Step 4: Run API static checks**

Run: `uv run ruff check src/security_review/api src/security_review/config.py apps tests/unit/api`
Expected: PASS.

Run: `uv run mypy src/security_review/api src/security_review/config.py`
Expected: PASS.

- [ ] **Step 5: Commit the API foundation**

```bash
git add pyproject.toml uv.lock src/security_review/config.py src/security_review/api apps/api tests/unit/api
git commit -m "feat: add FastAPI service foundation"
```

### Task 2: Secure upload and ZIP extraction

**Files:**
- Create: `src/security_review/uploads/__init__.py`
- Create: `src/security_review/uploads/archive.py`
- Create: `src/security_review/uploads/service.py`
- Test: `tests/unit/uploads/test_archive.py`
- Test: `tests/unit/uploads/test_service.py`

**Interfaces:**
- Consumes: `Settings` size/count limits and FastAPI `UploadFile` only at the API boundary.
- Produces: `ArchiveLimits`, `UnsafeArchiveError`, `extract_zip_safely(archive: Path, destination: Path, limits: ArchiveLimits) -> tuple[Path, ...]`, and `save_upload(stream: BinaryIO, destination: Path, max_bytes: int) -> Path`.

- [ ] **Step 1: Write failing archive attack tests**

```python
@pytest.mark.parametrize(
    "member_name",
    ["../escape.py", "/absolute.py", "C:/windows.py", "safe/../../escape.py"],
)
def test_rejects_escaping_archive_members(tmp_path: Path, member_name: str) -> None:
    archive = make_zip(tmp_path / "payload.zip", {member_name: b"print('x')"})
    with pytest.raises(UnsafeArchiveError, match="unsafe_path"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())


def test_rejects_duplicate_normalized_names(tmp_path: Path) -> None:
    archive = make_zip_entries(
        tmp_path / "payload.zip",
        [("src/app.py", b"one"), ("src\\app.py", b"two")],
    )
    with pytest.raises(UnsafeArchiveError, match="duplicate_path"):
        extract_zip_safely(archive, tmp_path / "out", ArchiveLimits())
```

Also construct ZIP metadata for a Unix symlink, an archive over `max_files`, and compressed entries whose declared extracted size exceeds `max_extracted_bytes`.

Run: `uv run pytest tests/unit/uploads -v`
Expected: FAIL because upload utilities do not exist.

- [ ] **Step 2: Implement preflight validation before writing any member**

```python
def normalized_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise UnsafeArchiveError("unsafe_path")
    if not path.parts:
        raise UnsafeArchiveError("empty_path")
    return path
```

Inspect every `ZipInfo` first. Reject encrypted entries, links detected from `external_attr`, duplicate normalized paths, count overflow, and total declared-size overflow. Only after all entries pass, stream-copy each file with a cumulative byte counter and `O_EXCL`-style collision protection.

- [ ] **Step 3: Implement bounded upload streaming**

Read in 64 KiB chunks, stop after `max_bytes`, remove the partial destination on error, and never call `UploadFile.read()` without a size. Provide typed `upload_too_large` and `unsupported_media_type` errors.

Run: `uv run pytest tests/unit/uploads -v`
Expected: PASS for every traversal, link, collision, size, and cleanup case.

- [ ] **Step 4: Commit secure upload handling**

```bash
git add src/security_review/uploads tests/unit/uploads
git commit -m "feat: secure uploaded source archives"
```

### Task 3: File and archive scan endpoints

**Files:**
- Create: `src/security_review/api/dependencies.py`
- Create: `src/security_review/api/schemas.py`
- Create: `src/security_review/api/routes/scans.py`
- Modify: `src/security_review/api/app.py`
- Test: `tests/unit/api/test_scan_endpoints.py`

**Interfaces:**
- Consumes: `scan_path`, upload utilities, `Settings`, and a temporary-directory factory.
- Produces: `POST /v1/scans/file` and `POST /v1/scans/archive`, both returning the canonical `ScanReport` JSON.

- [ ] **Step 1: Write failing endpoint and cleanup tests**

```python
def test_file_scan_returns_redacted_report(client: TestClient) -> None:
    raw = b'OPENAI_API_KEY="sk-test-1234567890"\n'
    response = client.post(
        "/v1/scans/file",
        files={"file": ("settings.py", raw, "text/x-python")},
    )
    assert response.status_code == 200
    assert response.json()["findings"][0]["rule_id"] == "SEC001"
    assert "sk-test-1234567890" not in response.text


def test_temporary_directory_is_removed_when_scanner_fails(
    app: FastAPI, recording_temp_factory: RecordingTempFactory
) -> None:
    app.dependency_overrides[get_scan_service] = lambda: RaisingScanService()
    app.dependency_overrides[get_temp_factory] = lambda: recording_temp_factory
    response = TestClient(app).post(
        "/v1/scans/file",
        files={"file": ("app.py", b"print('x')", "text/x-python")},
    )
    assert response.status_code == 500
    assert all(not path.exists() for path in recording_temp_factory.created)
```

Also test empty filenames, unsupported extensions, wrong MIME type on the archive endpoint, oversized upload, and unsafe ZIP error mapping.

Run: `uv run pytest tests/unit/api/test_scan_endpoints.py -v`
Expected: FAIL because scan routes do not exist.

- [ ] **Step 2: Implement thin routes with dependency-injected services**

```python
@router.post("/file", response_model=ScanReport)
def scan_file_upload(
    file: UploadFile,
    service: Annotated[ScanService, Depends(get_scan_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ScanReport:
    with TemporaryDirectory(prefix="secragraph-") as directory:
        target = save_validated_upload(file, Path(directory), settings)
        return service.scan(target)
```

Use `try/finally` or `TemporaryDirectory` context management so cleanup is guaranteed. Do not put scanner logic in route functions.

Run: `uv run pytest tests/unit/api/test_scan_endpoints.py -v`
Expected: PASS.

- [ ] **Step 3: Commit scan APIs**

```bash
git add src/security_review/api tests/unit/api
git commit -m "feat: expose secure scan endpoints"
```

### Task 4: Transactional PostgreSQL report repository

**Files:**
- Create: `alembic.ini`
- Create: `migrations/env.py`
- Create: `migrations/versions/20260920_0001_scan_reports.py`
- Create: `src/security_review/storage/__init__.py`
- Create: `src/security_review/storage/database.py`
- Create: `src/security_review/storage/models.py`
- Create: `src/security_review/storage/reports.py`
- Create: `src/security_review/ports.py`
- Test: `tests/unit/storage/test_reports.py`
- Test: `tests/integration/storage/test_postgres_reports.py`

**Interfaces:**
- Consumes: canonical `ScanReport` values.
- Produces: `ReportRepository.save(report: ScanReport) -> None`, `ReportRepository.get(scan_id: UUID) -> ScanReport | None`, `SqlAlchemyReportRepository`, and `create_session_factory(database_url: str)`.

- [ ] **Step 1: Define the repository protocol and failing contract tests**

```python
class ReportRepository(Protocol):
    def save(self, report: ScanReport) -> None: ...
    def get(self, scan_id: UUID) -> ScanReport | None: ...


def repository_contract(repository: ReportRepository, report: ScanReport) -> None:
    repository.save(report)
    assert repository.get(UUID(report.scan_id)) == report
```

Test the contract first against an in-memory fake, then against PostgreSQL marked `@pytest.mark.integration`. Add a transaction test that forces a child-finding insert failure and asserts no report row remains.

Run: `uv run pytest tests/unit/storage -v`
Expected: FAIL because the repository does not exist.

- [ ] **Step 2: Implement normalized persistence and Alembic migration**

Create `app.scan_reports`, `app.findings`, and `app.audit_events`. Store canonical finding fields in columns, tuple fields as PostgreSQL JSONB, and enforce `(scan_id, finding_id)` uniqueness. Use one transaction per `save` and ordered loading by file, line, rule, and ID.

```python
def save(self, report: ScanReport) -> None:
    with self._session_factory.begin() as session:
        session.add(ScanReportRow.from_domain(report))
        session.add_all(FindingRow.from_domain(report.scan_id, item) for item in report.findings)
```

Run: `uv run pytest tests/unit/storage -v`
Expected: PASS with the fake and mapper tests.

- [ ] **Step 3: Run the real PostgreSQL contract**

Run: `docker compose -f tests/compose.integration.yaml up -d postgres`
Expected: PostgreSQL becomes healthy.

Run: `uv run alembic upgrade head`
Expected: migration creates the `app` schema and tables.

Run: `uv run pytest tests/integration/storage/test_postgres_reports.py -v -m integration`
Expected: PASS, including rollback-on-failure.

- [ ] **Step 4: Commit persistence**

```bash
git add alembic.ini migrations src/security_review/storage src/security_review/ports.py tests/unit/storage tests/integration/storage
git commit -m "feat: persist scan reports in PostgreSQL"
```

### Task 5: Persisted scan and report retrieval endpoints

**Files:**
- Modify: `src/security_review/api/dependencies.py`
- Modify: `src/security_review/api/routes/scans.py`
- Create: `src/security_review/api/routes/reports.py`
- Modify: `src/security_review/application.py`
- Test: `tests/unit/api/test_report_endpoints.py`

**Interfaces:**
- Consumes: `ReportRepository` and all three renderers.
- Produces: persisted scan responses, `GET /v1/scans/{scan_id}`, and `GET /v1/scans/{scan_id}/report?format=markdown|sarif`.

- [ ] **Step 1: Write failing persistence and retrieval tests**

```python
def test_scan_is_saved_before_response(
    client: TestClient, repository: FakeReportRepository
) -> None:
    response = upload_sample(client)
    scan_id = response.json()["scan_id"]
    assert repository.get(UUID(scan_id)) is not None


def test_unknown_scan_returns_typed_404(client: TestClient) -> None:
    response = client.get(f"/v1/scans/{uuid4()}")
    assert response.status_code == 404
    assert response.json()["code"] == "scan_not_found"


def test_unsupported_report_format_is_typed_422(
    client: TestClient, saved_report: ScanReport
) -> None:
    response = client.get(f"/v1/scans/{saved_report.scan_id}/report?format=pdf")
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"
```

Run: `uv run pytest tests/unit/api/test_report_endpoints.py -v`
Expected: FAIL because reports are not persisted or retrievable.

- [ ] **Step 2: Add persistence to the application service**

```python
class ScanService:
    def __init__(self, reports: ReportRepository) -> None:
        self._reports = reports

    def scan(self, target: Path) -> ScanReport:
        report = scan_path(target, ScanLimits())
        self._reports.save(report)
        return report
```

Map repository unavailability to a stable `dependency_unavailable` 503. Do not claim success when persistence fails.

- [ ] **Step 3: Implement retrieval and content types**

Return JSON through the response model, Markdown as `text/markdown; charset=utf-8`, and SARIF as `application/sarif+json`. Use the same persisted report for every format.

Run: `uv run pytest tests/unit/api/test_report_endpoints.py -v`
Expected: PASS.

- [ ] **Step 4: Commit persisted report APIs**

```bash
git add src/security_review/api src/security_review/application.py tests/unit/api
git commit -m "feat: add persisted report APIs"
```

### Task 6: Docker Compose and API integration gate

**Files:**
- Create: `.env.example`
- Create: `.dockerignore`
- Create: `Dockerfile`
- Create: `compose.yaml`
- Create: `infra/postgres/init/001_roles.sql`
- Create: `tests/compose.integration.yaml`
- Create: `tests/integration/api/test_scan_lifecycle.py`
- Create: `scripts/wait_for_services.py`
- Modify: `src/security_review/api/routes/health.py`

**Interfaces:**
- Consumes: application image, Alembic migrations, PostgreSQL repository, and API routes.
- Produces: a local `api + postgres` stack now, with a reserved Qdrant service added by the intelligence plan.

- [ ] **Step 1: Write the failing API lifecycle integration test**

```python
@pytest.mark.integration
def test_uploaded_scan_can_be_retrieved_in_all_formats(live_client: httpx.Client) -> None:
    response = live_client.post(
        "/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)\n", "text/x-python")},
    )
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    assert live_client.get(f"/v1/scans/{scan_id}").status_code == 200
    assert live_client.get(f"/v1/scans/{scan_id}/report?format=markdown").status_code == 200
    sarif = live_client.get(f"/v1/scans/{scan_id}/report?format=sarif")
    assert sarif.headers["content-type"].startswith("application/sarif+json")
```

Run: `uv run pytest tests/integration/api/test_scan_lifecycle.py -v -m integration`
Expected: FAIL because no live stack exists.

- [ ] **Step 2: Build a non-root application image**

Use a multi-stage Python 3.11 slim image, copy the locked environment with `uv sync --frozen --no-dev`, create an unprivileged `app` user, expose 8000, and run `uvicorn apps.api.main:app --host 0.0.0.0 --port 8000`. Add a health check against `/health/live`.

- [ ] **Step 3: Define the local stack and database initialization**

Define named volumes, health checks, `depends_on` health conditions, no embedded production secrets, and environment interpolation from `.env`. Initialize separate owner and read-only roles; the intelligence plan grants the latter access only to its schema.

Run: `docker compose config`
Expected: valid `api` and `postgres` services with no unset required value.

- [ ] **Step 4: Run migrations and the live test**

Run: `docker compose up -d --build postgres api`
Expected: both services become healthy.

Run: `docker compose exec api uv run alembic upgrade head`
Expected: migration succeeds exactly once and is idempotent on a second invocation.

Run: `uv run pytest tests/integration/api/test_scan_lifecycle.py -v -m integration`
Expected: PASS.

- [ ] **Step 5: Run the API plan regression gate**

Run: `uv run pytest tests/unit tests/integration -v`
Expected: PASS.

Run: `uv run ruff check src apps tests scripts`
Expected: PASS.

Run: `uv run mypy src apps`
Expected: PASS.

Run: `docker compose down`
Expected: containers stop while named data volumes remain.

- [ ] **Step 6: Commit the reproducible backend stack**

```bash
git add .env.example .dockerignore Dockerfile compose.yaml infra tests/compose.integration.yaml tests/integration/api scripts src/security_review/api/routes/health.py
git commit -m "feat: run SecRAGraph with Docker Compose"
```
