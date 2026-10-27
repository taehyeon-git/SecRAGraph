# Automatic Case Corpus and One-Command Startup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare official CWE evidence matching all fixed evaluation cases and start the local platform through one command.

**Architecture:** A bounded official-source collector derives reviewed CWE IDs from evaluation labels, writes a verified local manifest and coverage report, and preserves a validated cache. A startup orchestrator calls it before keyless evaluations and Docker Compose, persists database credentials, provisions the first member, and applies the managed corpus only when an embedding key exists.

**Tech Stack:** Python 3.11+, Pydantic, httpx, Typer, Docker Compose, PostgreSQL, Qdrant, pytest.

**Spec:** docs/superpowers/specs/2026-10-27-auto-case-corpus-one-start.md

## Global Constraints

- No user source code or raw test source text is sent to the collector endpoint.
- No CWE-to-CVE inference. OSV queries require exact package coordinates.
- Automatic OSV uses only exact package coordinates found in supported lockfiles and reports unavailable/partial coverage without claiming safety.
- Official fetches use fixed MITRE HTTPS endpoints, bounded responses, no redirects, and verified IDs.
- Build artifacts and local credentials stay ignored by Git and Docker build context.
- Existing PostgreSQL volumes are never reset or silently rebound to new credentials.
- Keyless output distinguishes local LangGraph evaluation from provider-backed live RAG.

## Review Focus

- A changed case manifest requests an unexpected CWE: reject before network access.
- MITRE schema/version or response ID changes: reject the response and use a verified cache or explicit degraded status.
- A partially written cache or modified Markdown file: never accept it as verified official evidence.
- A stopped old PostgreSQL volume without a runtime secret file: fail with recovery guidance and preserve its data.
- Compose or provider errors after partial startup: retain state, report the failed stage, and allow a safe rerun.
- A lockfile with editable, Git, range-only, or malformed entries: skip them and never make a guessed OSV query.

---

### Task 1: Label the RAG question topics

**Files:** data/evaluation/rag_cases.json, src/security_review/evaluation/rag_models.py, tests/unit/evaluation/test_offline_rag.py

**Interfaces:** RagCase.knowledge_cwe_ids is a bounded tuple of reviewed CWE IDs. Empty is required for the unrelated abstention case. The existing offline RAG scoring stays unchanged.

- [ ] Add a failing test that reads all four labels, checks the exact topic map and rejects malformed IDs.
- [ ] Run the focused test and observe the expected failure.
- [ ] Add model validation and explicit case labels.
- [ ] Run the focused test and existing offline RAG evaluation.

### Task 2: Collect and verify the official case corpus

**Files:** src/security_review/intelligence/case_corpus.py, scripts/prepare_case_corpus.py, tests/unit/intelligence/test_case_corpus.py

**Interfaces:** prepare_case_corpus(repo_root: Path, cache_root: Path, *, offline: bool=False) -> CorpusPreparation. Result fields: root, manifest_path, coverage_path, status, document_count. Result status is official, cached, or fallback.

- [ ] Write failing tests for all 57 case records, 8 unique CWE topics, benign and abstention exclusions, and zero inferred CVEs.
- [ ] Add failing fake-HTTP tests for allowed URLs, payload/time bounds, redirects, malformed IDs/schema and duplicate records.
- [ ] Implement fixed-endpoint collection, document generation with MITRE rights text, atomic cache and manifest writes, then verify with load_verified_corpus.
- [ ] Add cache corruption, offline reuse and project-guide fallback tests.
- [ ] Run the collector test module and the keyless RAG evaluation.

### Task 3: Implement repeatable local startup

**Files:** scripts/local_up.py, tests/unit/scripts/test_local_up.py, .gitignore, .dockerignore

**Interfaces:** `uv run --frozen python -m scripts.local_up` is the public entrypoint; cache preparation uses Task 2's function. Compose always receives the persisted runtime environment.

- [ ] Write failing tests for secret creation/reuse, missing-state existing-volume refusal, first-member and rerun behavior, keyless/provider branches, and failed stages.
- [ ] Implement bounded subprocess orchestration with no shell, silent secrets, and readiness check.
- [ ] Ensure generated local files are ignored by Git and Docker build context.
- [ ] Run the startup unit tests and isolated Compose smoke.

### Task 4: Consolidate user instructions and verify

**Files:** README.md, docs/operations.md, docs/demo.md, docs/official-corpus.md, tests/unit/docs/test_documentation.py

- [ ] Update the documentation contract to require one canonical startup command and no Quick Start heading.
- [ ] Replace the manual startup recipe with that command; explain keyless/provider behavior, source provenance, cache, and existing-volume recovery.
- [ ] Run documentation tests, all unit tests, Ruff, mypy, Bandit, offline evaluations and isolated Compose smoke.
- [ ] Review the full diff for source rights, secret disclosure, false claims and unrelated changes.
- [ ] Commit, push a branch, open and review a PR, verify CI, then merge to main.

### Task 5: Automatic dependency evidence in scans

**Files:** src/security_review/intelligence/dependency_osv.py, src/security_review/intelligence/osv.py, src/security_review/orchestrator/scan_graph.py, src/security_review/application.py, src/security_review/cli.py, src/security_review/api/app.py, tests/unit/intelligence/test_dependency_osv.py, tests/unit/orchestrator/test_scan_graph.py

**Interfaces:** The scan workflow accepts an optional dependency auditor. CLI and production API install the bounded live auditor by default; deterministic evaluation can inject a fake or omit it. Results reuse the canonical Finding report model with OSV source links and explicit partial coverage warnings.

- [ ] Write failing tests for exact lockfile coordinates, ignored unpinned/path/Git entries, bounds, and no target execution.
- [ ] Write failing workflow tests for automatic OSV findings, no lockfile fast path, unavailable provider warnings, and report persistence.
- [ ] Implement bounded lockfile discovery and OSV batch screening, then fetch verified detail only for matching package versions.
- [ ] Wire CLI and production API through the same scan graph stage without changing the deterministic benchmark's baseline.
- [ ] Run unit, API, CLI, SARIF, and scanner benchmark tests.
