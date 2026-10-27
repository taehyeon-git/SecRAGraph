# Runtime CWE Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acquire and index source-verified official CWE documents for actual scans and new RAG questions without tying live coverage to evaluation cases.

**Architecture:** A per-CWE provider validates and caches MITRE responses, optionally replaces only the selected document in Qdrant, and returns references/warnings. The scan and knowledge graphs request evidence from actual finding CWE IDs or validated question candidates. Startup retains fixed evaluation reporting and preloads all rule CWE IDs.

**Tech Stack:** Python 3.11, FastAPI, LangGraph, Qdrant, httpx, Pydantic, pytest.

**Spec:** docs/superpowers/specs/2026-10-27-runtime-cwe-evidence.md

## Global Constraints

- User code is never executed or sent to MITRE. Only validated CWE numeric IDs go to fixed HTTPS endpoints.
- No CWE-to-CVE inference. OSV dependency matching remains package-version scoped.
- A runtime acquisition failure preserves deterministic findings and emits a coverage warning.
- Runtime indexing must never synchronize a small set against the startup corpus in a way that deletes other documents.
- Keep 64 scan IDs, eight question IDs, 12 seconds, four concurrent fetches, 256 KiB per response, 8 MiB total, 16 MiB API tmpfs cache, and 1,024 dedicated runtime Qdrant documents as upper bounds. Existing scan deadlines may be stricter.
- No provider key is needed to verify and cache a CWE document; live RAG indexing still requires embeddings.

## Review Focus

- A model emits an invalid or excessive CWE list: ignore it safely, preserve normal retrieval and a warning.
- A valid but unrelated CWE ID appears: official existence alone is not treated as proof of relevance or a vulnerability.
- MITRE is unavailable or returns a mismatched ID: do not attach an unverified source or erase existing findings.
- Concurrent requests for the same CWE: no partial cache accepted and no unrelated Qdrant points removed.
- A scan deadline is nearly spent: skip acquisition and return bounded partial coverage.

---

### Task 1: Bounded official CWE provider

**Files:** `src/security_review/intelligence/dynamic_cwe.py`, `src/security_review/intelligence/case_corpus.py`, `tests/unit/intelligence/test_dynamic_cwe.py`

**Interfaces:** `CweEvidenceResult.references_by_id: Mapping[str, SourceReference]`, `.warnings: tuple[str, ...]`; `CweEvidenceProvider.ensure(cwe_ids: Sequence[str], *, deadline: float | None = None) -> CweEvidenceResult`. Implement `LiveCweEvidenceProvider(cache_root, indexer=None, offline=False, ...)` with per-ID verified snapshots and optional `replace_documents` indexing into `secragraph-runtime-cwe-v1`. Reuse only the current MITRE response/document validation, not the set-wide cache or `sync_corpus`.

- [ ] Write and run failing tests for new ID fetch, verified cache hit, corruption, failed/mismatched response, offline reuse, cap/deadline, 16 MiB tmpfs eviction and sibling Qdrant document preservation.
- [ ] Implement the provider using the existing bounded MITRE validation and immutable manifest format; return content-free warnings for partial coverage.
- [ ] Run the focused tests, Ruff and mypy.

### Task 2: Scan graph integration

**Files:** `src/security_review/orchestrator/scan_graph.py`, `tests/unit/orchestrator/test_scan_graph.py`

**Interfaces:** `ScanGraphServices.cwe_evidence: CweEvidenceProvider | None`; a `prepare_cwe_evidence` node requests deduplicated deterministic finding IDs and adds verified official references before optional Qdrant retrieval.

- [ ] Write and run failing tests for novel finding CWE, duplicate IDs, 64-ID truncation, deadline/provider failure, preserved OSV and source citations.
- [ ] Add the graph node and warnings while preserving the current report baseline and all existing graph paths.
- [ ] Run the graph tests and scanner benchmark.

### Task 3: Question graph integration

**Files:** `src/security_review/orchestrator/knowledge_graph.py`, `src/security_review/orchestrator/state.py`, `tests/unit/orchestrator/test_knowledge_graph.py`

**Interfaces:** `KnowledgeServices.cwe_evidence: CweEvidenceProvider | None`; classifier accepts legacy route tokens and structured `{route,cwe_ids}` output. Explicit CWE IDs in the question take priority. A `prepare_cwe_evidence` node runs only on the RAG route before vector search.

- [ ] Write and run failing tests for an unseen natural-language topic, explicit CWE, malformed/oversized model IDs, Text2SQL isolation, no-key/service absence and citation validation.
- [ ] Implement bounded topic selection and acquisition warnings without treating model suggestions as confirmed vulnerabilities.
- [ ] Run knowledge graph and keyless RAG tests.

### Task 4: Wire live services and document behavior

**Files:** `src/security_review/api/app.py`, `src/security_review/application.py`, `src/security_review/cli.py`, `scripts/local_up.py`, `README.md`, `docs/architecture.md`, `docs/operations.md`, `docs/official-corpus.md`, `docs/threat-model.md`, relevant API/CLI/docs tests.

- [ ] Write failing API/CLI tests showing real scans use the optional provider and a new question can index an official document.
- [ ] Wire the provider into CLI and production API; offline mode makes no MITRE requests. Keep runtime cache in ignored build or bounded API tmpfs.
- [ ] Include all default scanner rule CWE IDs in startup acquisition; keep 53/4 as labeled evaluation results only.
- [ ] Update docs to distinguish evaluation cases, current rule coverage, on-demand scan/question documents, latency and keyless limitations.
- [ ] Run full local test suite, offline evaluations, Ruff, mypy, Bandit, isolated Compose smoke, and an official live smoke with a non-baseline CWE.
- [ ] Independent review, commit, PR, wait for CI, merge to main and verify main checks.
