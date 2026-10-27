# SecRAGraph local operations

Run these commands from the repository root with Docker Desktop's Linux engine (or a Linux Docker engine). The API and web containers run as UID 10001 with read-only root filesystems. Their only writable workspace is the 64 MiB `/tmp/secragraph` tmpfs, which is erased when a container stops. PostgreSQL and Qdrant data live in the named `postgres_data` and `qdrant_data` volumes.

## Start and check the stack

Install Python 3.11+, uv, and a Linux Docker engine. Run this one command from the repository root on Windows PowerShell or Linux:

~~~text
uv run --frozen python -m scripts.local_up
~~~

It collects official CWE topics matched to the current 120 scanner evaluation cases and four RAG evaluation questions plus scanner rules, writes a provenance manifest and case coverage under ignored build/auto-corpus, runs keyless evaluations, starts Compose with migrations and Qdrant bootstrap, seeds synthetic Text2SQL data only when both intelligence tables are empty, and prompts for the first member when needed. The 120/4 counts describe the current reproducible evaluation snapshots, not a limit on runtime scan inputs or CWE topics; new findings and model-backed questions can trigger additional verified CWE retrieval. The same command safely resumes an initialized stack. The --offline option disables MITRE collection, API scan-time automatic OSV and CWE lookup, and model-provider RAG for the local stack; standalone CLI scans need their own `--offline` flag; it reuses a verified corpus cache or labels the project-guide fallback as degraded. Docker builds and uv dependency installation may still require a complete local cache or network access; this option only disables MITRE, OSV, and model-provider calls. A live embedding key is optional: without SECRAGRAPH_OPENAI_API_KEY, no official documents are indexed for live API RAG, although keyless graph evaluation and scan report CWE references still work.

The command generates and reuses independent database passwords in ignored build/local/runtime.env. Protect and back up this file with the PostgreSQL volume. If the volume exists but the file is missing, startup stops: restore the original password file or recover the administrator password through the existing database's approved recovery procedure. Never delete the volume to fix a password mismatch. Do not paste credentials into source files, arguments, logs, or tickets. An existing postgres_data volume's administrator password is set at initialization and does not change when Compose environment values change.

Sign in at http://127.0.0.1:8501 with the member created by the hidden prompt. To suspend a member and revoke sessions, use docker compose -p secragraph --env-file build/local/runtime.env exec api /app/.venv/bin/security-review disable-user alice; unlock-user alice clears a failed-login lockout. Self-registration is disabled in the local production profile.

Inspect health and bounded logs without printing rendered Compose configuration:

~~~text
docker compose -p secragraph --env-file build/local/runtime.env ps -a
docker compose -p secragraph --env-file build/local/runtime.env logs --tail=100 api web postgres qdrant
~~~

The published API and web ports default to 8000 and 8501; all four published ports bind to host loopback. The Streamlit frontend accepts uploads up to 5 MiB and messages up to 8 MiB; the API enforces its separate 5,000,000-byte upload limit. Set API_PORT, WEB_PORT, POSTGRES_PORT, and QDRANT_PORT before startup if those host ports are occupied. Advanced Compose commands below need the same -p secragraph --env-file build/local/runtime.env arguments.

## OSV.dev package lookup

Normal scans detect supported public lockfile coordinates and query OSV.dev automatically. For a package outside the supported lockfiles, the CLI can still query an explicit version without an API key: `docker compose -p secragraph --env-file build/local/runtime.env exec api /app/.venv/bin/security-review osv-query --ecosystem PyPI --package jinja2 --version 2.4.1`. The authenticated endpoint and Dependency CVEs UI tab use the same live adapter. See [OSV lookup details](osv.md) for response bounds and the privacy boundary.

## On-demand CWE evidence

Normal API and CLI scans inspect the CWE IDs of findings produced by the current scan, fetch missing official MITRE records by ID, verify them, and attach official source references to the report. A model-backed RAG question can additionally propose relevant CWE IDs during its normal intent classification; explicit IDs in the question take priority. The provider checks those candidates against MITRE before optional Qdrant indexing. General-answer and Text2SQL routes do not fetch CWE documents. No source file or full question is sent to MITRE, and a CWE label is never converted into a guessed CVE.

The startup evaluation/rule corpus accepts up to 128 distinct CWE IDs and stops its network acquisition after 90 seconds, then uses a verified prior snapshot or the bundled project guide. This is separate from the smaller per-request runtime limits below.

The runtime provider uses a separate corpus ID from the startup case corpus, so refreshing the latter does not remove runtime documents. Verified per-ID snapshots are reused without checking the MITRE release on every cache hit; the recorded source revision identifies their age. A request can consider up to 64 scan CWE IDs or eight question CWE IDs. Bounds include four concurrent fetches, 256,000 bytes per official record, 8 MB of total official responses, a 12-second acquisition window, 16 MB of transient cache, and 1,024 runtime indexed documents. If any limit or source failure prevents complete coverage, the report or answer carries a scope warning; existing deterministic findings remain. These are resource limits, not a fixed list of supported CWE topics.

`uv run --frozen python -m scripts.local_up --offline` persists `SECRAGRAPH_AUTO_CWE_ENABLED=false` for the local API stack. `uv run security-review scan TARGET --offline` disables automatic CWE and OSV lookup for that standalone scan. For an online stack, set `SECRAGRAPH_AUTO_CWE_ENABLED=false` before running the startup command to disable only runtime CWE lookup. Without a model key, the API cannot serve live RAG answers even though scan-time CWE references can still be acquired.

## Advanced maintenance

The single startup command handles reader bootstrap, Alembic migration, the dedicated Qdrant collection, and a one-time synthetic Text2SQL seed. Rerun it to refresh the verified case corpus or apply it after setting a provider key. If a provider key is absent at a later manual Compose restart, live RAG remains disabled; rerun the startup command with the key to restore it. Extra PDF documents follow [the separate vetted-corpus procedure](official-corpus.md).

For migration recovery only, run the same project and saved runtime configuration:

```powershell
docker compose -p secragraph --env-file build/local/runtime.env run --rm migrate /app/.venv/bin/alembic upgrade head
```
For legacy reports created before the safe-evidence migration, `alembic upgrade head` replaces the stored `redacted_evidence` strings with a fixed privacy notice. The downgrade deliberately cannot reconstruct them. Previously exported reports, CI artifacts, database backups, and PostgreSQL WAL are outside this migration; identify and retire them separately under your data-retention policy. New reports never persist source-line evidence, but file paths and target names can still be sensitive.

## Backup, shutdown, and incidents

Create a PostgreSQL logical backup outside the repository; the dump can contain imported security data and reports. This example writes `secragraph-backup.sql` in your Documents folder; protect that file according to your local backup policy:

```powershell
docker compose -p secragraph --env-file build/local/runtime.env exec -T postgres pg_dump -U secragraph -d secragraph --no-owner --no-privileges > "$env:USERPROFILE\Documents\secragraph-backup.sql"
```

For an incident, capture service and health state first. A failed `reader-bootstrap` or `migrate` usually means the runtime administrator password does not match the existing volume, or the database is unavailable. A failed `qdrant-bootstrap` points to Qdrant startup or storage. Review only bounded logs and do not paste rendered Compose configuration, environment variables, raw uploads, or secrets into tickets:

```powershell
docker compose -p secragraph --env-file build/local/runtime.env ps -a
docker compose -p secragraph --env-file build/local/runtime.env logs --tail=200 --timestamps postgres reader-bootstrap migrate qdrant qdrant-bootstrap api web
docker compose -p secragraph --env-file build/local/runtime.env exec -T postgres pg_isready -U secragraph -d secragraph
docker compose -p secragraph --env-file build/local/runtime.env stop api
docker compose -p secragraph --env-file build/local/runtime.env up -d api
```

`docker compose -p secragraph --env-file build/local/runtime.env stop api` sends a graceful stop with a 20-second grace period; completed reports remain in PostgreSQL. To stop all containers while retaining data, use `docker compose -p secragraph --env-file build/local/runtime.env down`.

**Destructive operation — deletes local demo data:** `docker compose -p secragraph --env-file build/local/runtime.env down -v` removes the Compose project's named PostgreSQL and Qdrant volumes. Use it only when intentionally discarding *all* local reports, imported intelligence, and indexed documents, after backing up anything needed. It is not part of normal validation or password recovery.
