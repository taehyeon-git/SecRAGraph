# SecRAGraph Portfolio Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing local-first security portfolio safe to share and its RAG, scanner, and DevSecOps evidence independently inspectable without claiming unmeasured production quality.

**Architecture:** Keep the current scanner, application service, LangGraph, PostgreSQL, and Qdrant boundaries. Introduce safe evidence at the scanner boundary; a single-token gate at the API boundary; opt-in evaluation adapters outside production paths; a manifest and explicit managed-corpus sync around Qdrant; and CI artifacts plus full-stack smoke proof.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, SQLAlchemy/Alembic, Qdrant, LangGraph, pytest, Docker Compose, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-18-secragraph-portfolio-hardening-design.md`

## Global Constraints

- No execution of scanned or benchmark code.
- No network, Docker, PostgreSQL, external corpus, or API key required for the keyless evidence commands.
- No actual LLM answer-quality claim without a live provider run and human support review.
- No internet-facing API deployment or multi-user/tenant support claim.
- No GPL benchmark files copied into this MIT repository.
- Preserve existing CLI, scan/report schema, and deterministic synthetic benchmark contract unless a test explicitly proves a necessary change.
- Add a failing behavioral test before each production-code change; verify red and green with the existing `.venv` or `uv` environment.
- Use a repo-local `--basetemp build/<unique-name>` for pytest on this Windows sandbox; the sandbox default temp path is unwritable.

## Review Focus

- Arbitrary string adjacent to a finding remains absent from all report formats and from a reloaded report; Task 1 tests both unknown-token and recognized-secret siblings.
- Correct-token API requests work while missing/wrong tokens fail uniformly; health is reachable; Task 2 tests all three paths.
- Live evaluation with a missing key exits before constructing a provider, and a provider error is counted without publishing a false quality score; Task 3 tests both.
- A malformed external benchmark label or a missing case source does not silently shrink a performance denominator; Task 4 tests both.
- Corpus sync cannot delete untagged points or points in another corpus, including after a partial write error; Task 6 tests these paths.

---

### Task 1: Fail-closed scanner evidence and legacy rows

**Files:** `src/security_review/scanner/engine.py`, `src/security_review/scanner/redaction.py` or a focused sibling, `src/security_review/reporting/sarif.py`, `migrations/versions/20261018_0004_safe_evidence.py`, `tests/unit/scanner/test_engine.py`, `tests/unit/reporting/test_sarif.py`, `tests/integration/storage/test_postgres_reports.py`.

**Interfaces:** Produce `safe_evidence(rule_id: str) -> str`, an allowlisted constant marker for known rules and generic marker for extension rules. `scan_text_detailed` passes only this value to `Finding` and `finding_id`. SARIF `_fingerprint` uses rule/path/line rather than evidence/position-based occurrence so an unrelated earlier finding does not shift it. The migration overwrites old `app.findings.redacted_evidence` without altering row IDs or other report fields.

- [ ] Add tests with synthetic unknown canaries in `eval`, secret-assignment, and JS TLS lines. Assert absence from finding dump, JSON, Markdown, SARIF, and persisted/reloaded report; assert same rule/path/line yields the same ID/fingerprint across canary changes and adding an unrelated earlier finding does not shift a later fingerprint.
- [ ] Run the focused tests and observe a privacy assertion failure, not an import/setup failure.
- [ ] Implement constant rule-owned evidence and migration. Do not build evidence from any source-line substring. Preserve deduplication and finding metadata.
- [ ] Rerun focused tests; then scanner, reporting, and storage suites. Verify migration upgrade against a controlled legacy row when PostgreSQL is available.
- [ ] Commit this independently testable privacy boundary.

### Task 2: Single-user local API token gate

**Files:** `src/security_review/config.py`, `src/security_review/api/app.py`, new `src/security_review/api/auth.py`, `apps/web/client.py`, `apps/web/streamlit_app.py`, `compose.yaml`, `.env.example`, `tests/unit/api/test_auth.py`, `tests/unit/web/test_streamlit_client.py`, `tests/integration/test_compose_contract.py`, `tests/integration/container/test_runtime.py`.

**Interfaces:** `Settings.api_token: SecretStr | None`; one shared middleware/dependency protects every `/v1/*` when configured, comparing `Authorization: Bearer <token>` in constant time before multipart body buffering. `create_app` rejects `environment="production"` without a nonblank token, regardless of `testing`, while non-serving CLI maintenance commands remain usable. `SecRAGraphApiClient` accepts an optional token supplied by environment and sends the bearer header; it never renders or logs the token. `/health/*` remains exempt.

- [ ] Add tests for API startup configuration (including production plus `testing=True`), non-serving CLI maintenance in production without a token, missing/wrong/correct key on upload, retrieval, and knowledge routes, health exemption, token-free explicit development, and Streamlit client header behavior without secret in errors. A malformed multipart request without a token must return 401 before body parsing.
- [ ] Run focused tests and see the expected missing-control failures.
- [ ] Implement API startup validation and constant-time token comparison at one shared API boundary, then propagate the token through Compose, web, and documented curl commands; require a user-supplied token for production Compose with no committed sample credential. Update existing Compose/live API tests that construct production settings.
- [ ] Rerun focused API/web/Compose-contract tests and existing API suite.
- [ ] Commit the local access-control change.

### Task 3: Opt-in live RAG evaluation

**Files:** new `src/security_review/evaluation/live_rag.py`, new `scripts/run_live_rag_evidence.py`, `tests/unit/evaluation/test_live_rag.py`; reuse `offline_rag.py`, `rag_models.py`, and provider adapters without changing the keyless runner.

**Interfaces:** `run_live_evaluation(...)` takes injected chat/embedding adapters for tests and an explicit bounded case list; the separate CLI adapter factory requires `SECRAGRAPH_OPENAI_API_KEY` before constructing any provider and writes `build/evidence/rag-live.json` only when invoked. Injected offline fakes do not need a key. Result has model IDs, input digests, route/retrieval/citation/abstention counts with denominators, latency/errors, and `factual_support="requires_human_review"` for every generated answer.

- [ ] Add a CLI/factory test for no-key fast failure before provider construction; use injected fake-provider tests for at-most-four bounded cases, correct metrics and citations, provider failure, and absence of a machine factuality claim.
- [ ] Run tests red, implement the separate opt-in runner with fresh in-memory Qdrant, then run focused tests green and rerun existing keyless RAG evidence.
- [ ] Commit the live evaluator without any key or generated live answer.

### Task 4: External scanner benchmark adapter

**Files:** new `src/security_review/evaluation/external_benchmark.py`, new `scripts/run_external_scanner_benchmark.py`, `tests/unit/evaluation/test_external_benchmark.py`.

**Interfaces:** Accept a local OWASP Benchmark for Python checkout, an exact 40-character upstream commit SHA and expected-results SHA-256. Require actual `git HEAD` to equal that SHA and tracked `expectedresults-0.1.csv` plus `testcode/` to be clean; parse labels and `testcode/BenchmarkTestNNNNN.py` as UTF-8 data only, and scan each case separately without import/execution. Map declared broad-CWE challenges `CWE-78 → PY002` and `CWE-502 → PY004`, explicitly stating sink mismatch (`sh -c`, `pickle.loads`) and expected blind spots. Report case-level TP/FP/FN/TN, missing/unsupported cases, and denominators separately from the line-level synthetic benchmark. Fail on missing or ambiguous challenge-case sources. Do not vendor the GPL corpus.

- [ ] Add temporary fixture checkout tests for true/false labels, unsupported CWE, missing source, malformed duplicate labels, wrong hashes, and exact case-level counts. A missing challenge source must yield a bounded error record with missing IDs and the original labeled denominator, then a nonzero CLI exit.
- [ ] Run tests red, implement bounded file and CSV parsing plus `scan_text_detailed`, run focused tests green.
- [ ] Run the existing 39-case benchmark to prove its contract is unchanged; commit adapter and fixture tests only.

### Task 5: Manifest-verified knowledge ingestion

**Files:** new `src/security_review/intelligence/manifest.py`, `src/security_review/intelligence/ingestion.py`, `src/security_review/cli.py`, `tests/unit/intelligence/test_manifest.py`, `tests/unit/intelligence/test_ingestion.py`, `data/knowledge/manifest.json`.

**Interfaces:** `load_verified_corpus(root: Path, manifest_path: Path) -> VerifiedCorpus` validates a versioned manifest containing corpus ID and per-Markdown relative path, publisher/source URL, license, source revision/date, and raw SHA-256 before any provider write. It reads each file once and constructs `KnowledgeDocument` from the same digest-verified bytes, with source URL, optional validated `corpus_id`, and a bounded receipt under ignored `build/evidence/ingest-receipt.json` only on explicit ingestion. A valid zero-document manifest returns an empty desired corpus for preview/sync, not an ingestion success. `chunk_document` incorporates `corpus_id` into managed document/point IDs while preserving existing IDs when it is absent. Existing `load_knowledge_documents` remains for explicitly unverified demo use.

- [ ] Add tests for valid local manifest, zero-document manifest, changed bytes, bad/escaping path, duplicate path, missing document, invalid URL/license/date, and no-provider-write on invalid manifest. Include a test changing the source after snapshot validation; the provider must receive only verified bytes or a failure, never unverified replacement content.
- [ ] Run red, implement validated loader and opt-in CLI entry. Keep sample metadata truthful: project-authored document, not an upstream CVE source.
- [ ] Run focused ingestion and CLI tests green; commit verified ingestion.

### Task 6: Explicit managed-corpus reconciliation

**Files:** `src/security_review/intelligence/qdrant_retriever.py`, `src/security_review/cli.py`, `tests/unit/intelligence/test_qdrant_retriever.py`, `tests/integration/intelligence/test_qdrant.py`.

**Interfaces:** `preview_corpus_sync(corpus_id, desired_document_ids)` returns bounded stale managed IDs; `sync_corpus(corpus_id, chunks, *, apply: bool, allow_empty: bool = False)` previews by default and on apply calls `replace_documents` for each desired document to remove its stale chunks, then deletes absent documents in that corpus only. Store `corpus_id` in managed point payload and use corpus+generation guards on deletion. Reject mixed/missing corpus IDs on managed chunks. Empty desired corpus is previewable but apply requires `allow_empty=True` and CLI `--allow-empty`. If any write fails, surface an error and do not run stale-document deletion; a repeated sync is the documented repair path. Old untagged points require a separately documented rebuild and are never auto-deleted.

- [ ] Add in-memory Qdrant tests for removed/renamed file, same-identity content change with fewer chunks, same-path another corpus, same-path untagged legacy point, unchanged corpus, invalid/empty desired set, explicit `allow_empty`, and injected upsert failure that raises without stale-document deletion. Do not assert an atomic swap of partially overwritten selected-corpus points.
- [ ] Run red, implement bounded snapshot and generation-guarded delete. Wire explicit CLI preview/apply flags only for manifest-verified corpus.
- [ ] Run focused Qdrant unit/integration tests green; commit managed sync.

### Task 7: Inspectable CI, full-stack smoke, and demo clarity

**Files:** `.github/workflows/ci.yml`, `tests/integration/test_compose_contract.py`, `tests/integration/container/test_runtime.py` or new bounded smoke script, `apps/web/client.py`, `apps/web/streamlit_app.py`, `tests/unit/web/test_streamlit_client.py`.

**Interfaces:** Quality job uploads only synthetic `build/evidence/{rag,scanner}.{json,md}` artifacts, and only on trusted `main` pushes. A Compose smoke job uses a unique project/port range, generated unprinted secrets, and ephemeral storage; it checks API+web health and an authenticated synthetic upload/retrieval, and cleans up its exact project even on failure. All published Compose ports remain loopback-bound. UI explicitly labels offline proof versus provider-backed Q&A and surfaces downloadable JSON/Markdown/SARIF for one scan.

- [ ] Add behavior tests for loopback ports, UI no-key guidance, report-link/client handling, and smoke-script failure cleanup; run red.
- [ ] Implement artifact upload, smoke job/script, and UI changes; run focused tests green and validate Compose config with synthetic env values.
- [ ] Commit CI and demo changes. Do not publish generated user-code evidence.

### Task 8: Documentation, cross-checks, and integration

**Files:** `README.md`, `docs/demo.md`, `docs/operations.md`, `docs/threat-model.md`, `SECURITY.md`, `CHANGELOG.md`, `pyproject.toml`, `src/security_review/__init__.py`, `data/samples/README.md` as needed.

**Interfaces:** No new runtime interface. Explain authentication setup, legacy-report migration, keyless versus live RAG, synthetic versus external scanner scores, provenance/sync, downloadable CI artifacts, and exact residual limitations. Link a current `main`/CI run after publication; do not imply `v0.1.0` contains this work.

- [ ] Run keyless RAG and scanner evidence, record actual counts, review all generated outputs for secrets, update docs with observed rather than predicted numbers, and bump the unreleased package version for changed report/auth behavior.
- [ ] Run Ruff format/check, mypy, Bandit, pytest (infra-backed where available), Compose validation/smoke, dependency audit, and `git diff --check`. Resolve all failures or state the exact blocked checks.
- [ ] Request an independent whole-branch code/security review. Correct Important/Critical findings with red-green tests, then rerun all applicable checks.
- [ ] Commit final docs and fixes, verify remote `main` has not moved, publish a fast-forward-equivalent commit/tree to `main`, and read back the remote tree/checks.
