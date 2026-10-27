# Automatic case corpus and one-command startup

## Goal

Make the fixed scanner and RAG evaluation cases drive a bounded, attributable local security knowledge corpus, and provide one repeatable local startup command for the portfolio demo.

## Source and case boundary

- The 53 scanner cases are author-created synthetic tests. A positive expected rule maps through the checked-in scanner rule registry to a CWE; benign cases remain explicitly unlabelled. The four RAG questions gain reviewed CWE topic labels: SQL injection 89, exposed credentials 200, unrelated abstention none, and token signature verification 347. These are retrieval topics, not assertions that the question is itself an exploited vulnerability.
- The collector requests only the union of these CWE IDs from the official MITRE CWE API. Its URLs and response sizes are fixed and bounded; arbitrary URLs from case files are never fetched. It records source URL, version, fetch date, SHA-256, publisher and license with every generated Markdown document. Reproduced MITRE content includes the required attribution and license text.
- Exact package ecosystem, name and version are absent from these cases, so no CVE is inferred. Existing OSV package lookup remains a separate explicit operation.
- For a user's scan target, supported lockfiles with exact versions are parsed locally without executing the project. The scan pipeline automatically sends only valid package ecosystem/name/version coordinates to OSV.dev. Unpinned or unsupported entries are skipped with coverage diagnostics. A matching OSV advisory produces a source-linked dependency finding; a provider failure is not presented as a clean result. The explicit package lookup remains available for exceptional cases.
- The output under ignored build/auto-corpus is a verified manifest, documents and a 57-case coverage report. Downloaded content remains local and is not committed. An intact verified cache can be reused offline. If neither official data nor cache is available, the pipeline uses only the checked-in project-authored guide and reports degraded provenance.
- Managed Qdrant sync uses the verified manifest only after the application is healthy and an embedding provider key exists. Keyless execution still runs the real local LangGraph/Qdrant evaluation with deterministic adapters; it does not claim that the API can answer with indexed official content.

## Startup boundary

- The single documented entrypoint is `uv run --frozen python -m scripts.local_up` from the repository root. It prepares the case corpus, runs keyless evaluations, starts the loopback-only Docker Compose stack, provisions the first member through a hidden local prompt, checks readiness, and optionally applies the corpus if a provider key is present.
- Random database credentials are generated once and reused from an ignored local runtime file. If the PostgreSQL volume exists without that file, startup stops with recovery instructions; it never silently changes a password or deletes a volume. Repeated startup is idempotent and does not recreate a member.
- Network or source failures are shown as degraded corpus status. Docker, migration, member creation, readiness, evaluation, and provider-sync failures return a nonzero status with bounded diagnostics. No step prints secrets or rendered Compose configuration.
- Automatic OSV queries have a bounded package and response budget and are triggered only for exact lockfile records. The scanner's deterministic rule baseline and keyless benchmark remain independently reproducible; online OSV results are reported as a distinct enrichment stage.
- PDF acquisition remains explicitly managed through the existing manifest mechanism. The automatic path handles the small relevant official CWE text set only; it does not crawl or download arbitrary PDFs.

## Acceptance evidence

Focused tests cover case mapping, no fabricated CVE, official response validation, bounded network access, cache/fallback, manifest integrity, license attribution, exact lockfile extraction and automatic OSV enrichment, startup secret reuse and volume protection, first-member behavior, and keyless/provider branches. Full Ruff, mypy, Bandit, unit/integration evaluation, Compose smoke, and main CI must pass before integration.
