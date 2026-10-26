# SecRAGraph local operations

Run these commands from the repository root with Docker Desktop's Linux engine (or a Linux Docker engine). The API and web containers run as UID 10001 with read-only root filesystems. Their only writable workspace is the 64 MiB `/tmp/secragraph` tmpfs, which is erased when a container stops. PostgreSQL and Qdrant data live in the named `postgres_data` and `qdrant_data` volumes.

## Start and check the stack

Set two independent, URL-safe database passwords in the current Windows PowerShell 5.1 or PowerShell 7 session. Member accounts use a hidden password prompt after startup; no shared API token is required for the web UI. Do not paste generated values into source files, command arguments, or logs. Set `SECRAGRAPH_OPENAI_API_KEY` only if provider-backed answers or document ingestion are needed. For official PDF ingestion, follow the explicit acquisition and local manifest procedure in [official corpus guidance](official-corpus.md); PDF parsing runs in the CLI process, outside Compose API resource limits.

```powershell
$adminBytes = New-Object byte[] 32
$readerBytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($adminBytes)
    $rng.GetBytes($readerBytes)
} finally {
    $rng.Dispose()
}
$env:POSTGRES_PASSWORD = [BitConverter]::ToString($adminBytes).Replace('-', '')
$env:SECRAGRAPH_READER_PASSWORD = [BitConverter]::ToString($readerBytes).Replace('-', '')
docker compose config --quiet
docker compose build api web
docker compose up -d
docker compose ps -a
docker compose exec api /app/.venv/bin/security-review create-user alice
```

`create-user` asks for and confirms a password without terminal echo. Choose a unique password of 12–1024 UTF-8 bytes. Sign in at `http://127.0.0.1:8501`. To suspend a member and revoke sessions, run `docker compose exec api /app/.venv/bin/security-review disable-user alice`; after a failed-login lockout, `unlock-user alice` clears the lock. Self-registration is disabled by default and should stay disabled in the local production Compose profile.

For an **existing** `postgres_data` volume, use its already initialized PostgreSQL administrator password instead of generating a new `POSTGRES_PASSWORD`. `POSTGRES_PASSWORD` configures PostgreSQL only on first initialization; changing the environment variable later does not rotate the stored role password. The reader bootstrap updates the reader role only after it can authenticate with the administrator password. If a rotation is intended, first start with the matching existing administrator value, enter `docker compose exec postgres psql -U secragraph -d secragraph`, run `\password secragraph` interactively, and then update the session's `POSTGRES_PASSWORD` to the new value before restarting services. The interactive prompt keeps the new value out of shell history. Do not remove volumes to resolve a password mismatch.

Inspect health and application logs without printing Compose's rendered environment (which contains credentials):

```powershell
docker compose ps -a
docker compose exec -T api /app/.venv/bin/python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=5).status)"
docker compose exec -T web /app/.venv/bin/python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=5).status)"
docker compose logs --tail=100 api web postgres qdrant
```

The published API and web ports default to `8000` and `8501`; all four published ports bind to host loopback. The Streamlit frontend accepts uploads up to 5 MiB and messages up to 8 MiB; the API enforces its separate 5,000,000-byte upload limit. Set `API_PORT`, `WEB_PORT`, `POSTGRES_PORT`, and `QDRANT_PORT` before startup if those host ports are occupied. Keep the password variables available in the same session for every `docker compose` command.

Protected `/v1/*` routes accept `Authorization: Session <member-session>` after login. Only `/v1/auth/login` (and development-only registration when explicitly enabled) is unauthenticated; health endpoints are separate. The Streamlit container holds each login session in its server-side state and clears it on logout or a 401. Reports are stored with a member owner and foreign report IDs return 404 for JSON, Markdown, and SARIF. Reports created before ownership was added have no owner and are visible only to an optional operator token. `SECRAGRAPH_API_TOKEN` remains an **optional** Bearer credential for trusted CLI/CI automation and is never passed to the web container. Rotate a disclosed operator token by changing its local value and recreating `api`; disable affected members if their sessions may have been exposed. Avoid copying rendered Compose configuration, which expands database secrets.

## OSV.dev package lookup

The CLI can query an explicit package version without an API key: `docker compose exec api /app/.venv/bin/security-review osv-query --ecosystem PyPI --package jinja2 --version 2.4.1`. The authenticated endpoint and Dependency CVEs UI tab use the same live adapter; the named package/version is sent to OSV.dev. See [OSV lookup details](osv.md) for response bounds and interpretation.

## Migrate and load sample data

`docker compose up -d` runs the reader bootstrap, Alembic migration, and Qdrant collection bootstrap before starting the API. Repeat or inspect them explicitly with:

```powershell
docker compose run --rm migrate /app/.venv/bin/alembic upgrade head
docker compose run --rm migrate /app/.venv/bin/security-review import-intelligence --cwe /app/data/samples/cwe.csv --cve /app/data/samples/cve.csv
docker compose run --rm qdrant-bootstrap /app/.venv/bin/security-review bootstrap-qdrant
```

Managed document sync validates [the local manifest](../data/knowledge/manifest.json) before writing. The preview needs running Qdrant but no model key; applying nonempty documents calls the embedding provider and requires a real API key. To retain the local provenance receipt when running the one-shot container, bind only the ignored evidence directory:

```powershell
docker compose run --rm qdrant-bootstrap /app/.venv/bin/security-review sync-corpus /app/data/knowledge
New-Item -ItemType Directory -Force -Path build/evidence | Out-Null
$evidenceMount = "$(Join-Path (Get-Location) 'build/evidence'):/evidence"
docker compose run --rm --volume $evidenceMount -e SECRAGRAPH_OPENAI_API_KEY qdrant-bootstrap /app/.venv/bin/security-review sync-corpus /app/data/knowledge --apply --receipt /evidence/ingest-receipt.json
```

`build/evidence/ingest-receipt.json` records manifest and source digests, publisher, license, revision/date, and document counts; it may be sensitive and is not a public CI artifact. Changed/removed documents are reconciled only within their managed corpus. A zero-document deletion needs the additional `--allow-empty` flag. The update is not an atomic Qdrant transaction: a provider or Qdrant failure can leave a partial selected corpus. Inspect the error and rerun the same pinned manifest to converge; do not assume rollback. `ingest-documents` remains available for legacy, manifest-free demo ingestion, but has no provenance verification.

For legacy reports created before the safe-evidence migration, `alembic upgrade head` replaces the stored `redacted_evidence` strings with a fixed privacy notice. The downgrade deliberately cannot reconstruct them. Previously exported reports, CI artifacts, database backups, and PostgreSQL WAL are outside this migration; identify and retire them separately under your data-retention policy. New reports never persist source-line evidence, but file paths and target names can still be sensitive.

## Backup, shutdown, and incidents

Create a PostgreSQL logical backup outside the repository; the dump can contain imported security data and reports. This example writes `secragraph-backup.sql` in your Documents folder; protect that file according to your local backup policy:

```powershell
docker compose exec -T postgres pg_dump -U secragraph -d secragraph --no-owner --no-privileges > "$env:USERPROFILE\Documents\secragraph-backup.sql"
```

For an incident, capture service and health state first. A failed `reader-bootstrap` or `migrate` usually means the runtime administrator password does not match the existing volume, or the database is unavailable. A failed `qdrant-bootstrap` points to Qdrant startup or storage. Review only bounded logs and do not paste rendered Compose configuration, environment variables, raw uploads, or secrets into tickets:

```powershell
docker compose ps -a
docker compose logs --tail=200 --timestamps postgres reader-bootstrap migrate qdrant qdrant-bootstrap api web
docker compose exec -T postgres pg_isready -U secragraph -d secragraph
docker compose stop api
docker compose up -d api
```

`docker compose stop api` sends a graceful stop with a 20-second grace period; completed reports remain in PostgreSQL. To stop all containers while retaining data, use `docker compose down`.

**Destructive operation — deletes local demo data:** `docker compose down -v` removes the Compose project's named PostgreSQL and Qdrant volumes. Use it only when intentionally discarding *all* local reports, imported intelligence, and indexed documents, after backing up anything needed. It is not part of normal validation or password recovery.
