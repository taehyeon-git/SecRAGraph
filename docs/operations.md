# SecRAGraph local operations

Run these commands from the repository root with Docker Desktop's Linux engine (or a Linux Docker engine). The API and web containers run as UID 10001 with read-only root filesystems. Their only writable workspace is the 64 MiB `/tmp/secragraph` tmpfs, which is erased when a container stops. PostgreSQL and Qdrant data live in the named `postgres_data` and `qdrant_data` volumes.

## Start and check the stack

Set two independent, URL-safe passwords in the current Windows PowerShell 5.1 or PowerShell 7 session. Do not paste the generated values into source files, command arguments, or logs. Set `SECRAGRAPH_OPENAI_API_KEY` only if provider-backed answers or document ingestion are needed.

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
```

For an **existing** `postgres_data` volume, use its already initialized PostgreSQL administrator password instead of generating a new `POSTGRES_PASSWORD`. `POSTGRES_PASSWORD` configures PostgreSQL only on first initialization; changing the environment variable later does not rotate the stored role password. The reader bootstrap updates the reader role only after it can authenticate with the administrator password. If a rotation is intended, first start with the matching existing administrator value, enter `docker compose exec postgres psql -U secragraph -d secragraph`, run `\password secragraph` interactively, and then update the session's `POSTGRES_PASSWORD` to the new value before restarting services. The interactive prompt keeps the new value out of shell history. Do not remove volumes to resolve a password mismatch.

Inspect health and application logs without printing Compose's rendered environment (which contains credentials):

```powershell
docker compose ps -a
docker compose exec -T api /app/.venv/bin/python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=5).status)"
docker compose exec -T web /app/.venv/bin/python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=5).status)"
docker compose logs --tail=100 api web postgres qdrant
```

The published API and web ports default to `8000` and `8501`; all four published ports bind to host loopback. The Streamlit frontend accepts uploads up to 5 MiB and messages up to 8 MiB; the API enforces its separate 5,000,000-byte upload limit. Set `API_PORT`, `WEB_PORT`, `POSTGRES_PORT`, and `QDRANT_PORT` before startup if those host ports are occupied. Keep the password variables available in the same session for every `docker compose` command.

## Migrate and load sample data

`docker compose up -d` runs the reader bootstrap, Alembic migration, and Qdrant collection bootstrap before starting the API. Repeat or inspect them explicitly with:

```powershell
docker compose run --rm migrate /app/.venv/bin/alembic upgrade head
docker compose run --rm migrate /app/.venv/bin/security-review import-intelligence --cwe /app/data/samples/cwe.csv --cve /app/data/samples/cve.csv
docker compose run --rm qdrant-bootstrap /app/.venv/bin/security-review bootstrap-qdrant
```

Document ingestion calls the embedding provider and requires a real API key in the host environment. With `SECRAGRAPH_OPENAI_API_KEY` set in the current session:

```powershell
docker compose run --rm -e SECRAGRAPH_OPENAI_API_KEY qdrant-bootstrap /app/.venv/bin/security-review ingest-documents /app/data/knowledge
```

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
