# SecRAGraph Verified PDF Corpus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow carefully vetted local PDF security publications to become page-cited RAG evidence without bulk crawling or silently trusting unverified bytes.

**Architecture:** The existing managed manifest verifies original file bytes before decoding. A small pypdf adapter extracts bounded text page by page into the already page-aware `KnowledgeDocument` model. `sync-corpus` uses the existing Qdrant reconciliation and document citation path; an official-source guide explains acquisition, rights, publication status, and local-only evidence.

**Tech Stack:** Python 3.11, pypdf, Pydantic, Qdrant adapter, pytest, existing keyless RAG evaluator.

**Spec:** `docs/superpowers/specs/2026-10-27-membership-scanner-rag-design.md`

## Global Constraints

- PDF is accepted only by the hash-verified managed-corpus manifest, not as an API upload or arbitrary recursive `ingest-documents` input.
- No code, attachment, JavaScript, external link, or scanned PDF content is executed. No OCR; image-only/encrypted/corrupt PDF is explicitly rejected.
- The original PDF's SHA-256, publisher, source URL, source revision/date, and rights note are mandatory manifest metadata.
- At most 5 MB raw bytes per PDF, 20 MB per corpus, 200 pages per PDF, 100,000 extracted characters per page, and 2,000,000 extracted characters per PDF; existing aggregate document/chunk bounds still apply.
- A verified hash is provenance, not proof that a PDF is benign. Parsing remains an opt-in CLI activity with trusted local sources and container resource limits; no public PDF upload endpoint is added.
- Page numbers and stable corpus/path identity survive chunking, Qdrant payload, retrieval, and citations. Changed bytes replace managed old chunks, not unrelated corpora.

## Review Focus

1. A small compressed PDF can expand its page content enormously: reject obvious oversized uncompressed page streams where pypdf exposes their length, run trusted-source extraction inside the existing container CPU/memory limits, and document that these checks do not prove a malicious PDF cannot exhaust resources (Task 1 test/documentation).
2. Manifest path is symlink/reparse-point or escapes corpus: reject before parser invocation (Task 1 test).
3. Valid PDF with no extractable text: return a distinct image-only/unextractable error, never index an empty placeholder (Task 1 test).
4. Changed PDF at same corpus/path: new pages replace old managed chunks while other corpora remain (Task 2 test).
5. Retrieved PDF citation has original source URL and one-based page metadata, not a fabricated Markdown source (Task 2 test).

---

### Task 1: Digest-verified bounded PDF extraction

**Files:**
- Modify: `pyproject.toml`, `uv.lock`, `src/security_review/intelligence/manifest.py`
- Create: `src/security_review/intelligence/pdf_ingestion.py`
- Modify: `tests/unit/intelligence/test_manifest.py`
- Create: `tests/unit/intelligence/test_pdf_ingestion.py`

**Interfaces:**
- `extract_pdf_pages(raw_pdf: bytes, *, source_path: str, title: str, source_url: str, corpus_id: str) -> tuple[KnowledgeDocument, ...]` returns one document per nonempty PDF page, setting the existing `page` field to a one-based number.
- `ManifestEntry.path` accepts `.pdf` only in the verified corpus; `load_verified_corpus` checks raw SHA-256 first, then dispatches to PDF extraction. Manifest version stays `1` because metadata fields are unchanged and the extension is additive.
- `ManifestError` maps extraction failures to stable content-free codes such as `invalid_pdf`, `encrypted_pdf`, `pdf_too_many_pages`, `pdf_text_too_large`, `pdf_text_unavailable`; no source text appears in errors.

- [ ] **Step 1: Add pypdf dependency and lock** using the project package manager, and write failing unit tests with generated tiny text PDFs plus corrupt/encrypted/image-only/oversized fixtures.
- [ ] **Step 2: Run red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/intelligence/test_pdf_ingestion.py tests/unit/intelligence/test_manifest.py`.
- [ ] **Step 3: Implement** strict manifest dispatch and bounded page extraction, preserving existing Markdown behavior and link/path checks.
- [ ] **Step 4: Run green** with the same tests and `tests/unit/intelligence/test_corpus_sync.py`.
- [ ] **Step 5: Commit** the parser, manifest, lock, and tests.

### Task 2: Managed-corpus sync and page-cited RAG evidence

**Files:**
- Modify: `src/security_review/intelligence/qdrant_retriever.py` only if existing page payload handling needs correction.
- Modify: `tests/unit/intelligence/test_corpus_sync.py`, `tests/unit/intelligence/test_qdrant_retriever.py`, `tests/unit/evaluation/test_offline_rag.py`
- Create: `docs/official-corpus.md`
- Modify: `README.md`, `docs/demo.md`, `docs/architecture.md`, `docs/threat-model.md`

**Interfaces:**
- Existing `security-review sync-corpus ROOT --apply` accepts a manifest that includes vetted PDFs and retains its preview/apply/receipt semantics.
- The guide lists final versus draft NIST/CISA publications, canonical URLs, rights caveats, version-date checks, hash/manifest procedure, no-provider-key offline verification, and explicit provider-key/human-review limits.

- [ ] **Step 1: Write failing tests** for end-to-end page metadata from verified PDF through chunks/Qdrant retrieval/knowledge graph citation, stable repeat sync, changed-version cleanup, cross-corpus preservation, and adversarial PDF text that is handled only as lower-trust cited data rather than a graph instruction.
- [ ] **Step 2: Run red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/intelligence/test_corpus_sync.py tests/unit/evaluation/test_offline_rag.py`.
- [ ] **Step 3: Implement** any missing page propagation; write the acquisition guide and add a minimal, reviewed official-source catalog without committing PDF binaries.
- [ ] **Step 4: Run green** plus `python -m scripts.run_rag_evidence`, Ruff, mypy, and local official-PDF dry-run if retrieval is available. Report any missing live provider key instead of inventing an LLM quality score.
- [ ] **Step 5: Commit** integration tests and documentation.
