# SecRAGraph Offline RAG Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the real knowledge LangGraph and Qdrant adapter without credentials, then show a reproducible, cited trace and honest contract-evaluation results.

**Architecture:** Keep the production provider/API boundary unchanged. A demo-only embedding and chat adapter drive the existing graph against an in-memory Qdrant collection built from the bundled guide; a small evaluator records allowlisted node updates and compares them with fixed labels. Correct RAG `sources` to include only cited chunks.

**Tech Stack:** Python 3.11+, LangGraph, qdrant-client local mode, Pydantic, pytest, stdlib `hashlib`/`json`/`argparse`.

**Spec:** `docs/superpowers/specs/2026-10-09-secragraph-portfolio-evidence-design.md` §§1–3, 5–6.

## Global Constraints

- The default demo executes after dependency installation with no API key, Docker, PostgreSQL, or network call.
- It reads only the original bundled Markdown guide and never executes target code.
- Evaluation scores are workflow/retrieval/citation-contract scores, never semantic LLM-quality claims.
- Public `SourceReference` remains metadata-only; excerpts appear only in bounded demo evidence from the bundled guide.
- Generated evidence goes under ignored `build/evidence/`; the demo exits nonzero on failed labels.
- No internet API deployment or authenticated-service work.

## Review Focus

1. An unknown `[source:id]` must remain a typed graph failure, not appear as a successful demo; a valid but irrelevant cited chunk must also fail the labeled answer case (Task 3 tests).
2. A searched but uncited chunk must not appear in public `sources` (Task 1 test).
3. A query with no relevant chunks must stop after the configured retry bound and abstain (Task 3 test).
4. A malformed/duplicate case ID must fail manifest loading before Qdrant setup (Task 2 test).
5. Trace/Markdown output must never contain complete raw LangGraph state, uncited source text, or an unbounded excerpt (Task 4 test).

## File map

| File | Responsibility |
| --- | --- |
| `src/security_review/orchestrator/knowledge_graph.py` | Filter cited sources and expose a single final-state validator used by invoke and stream paths. |
| `src/security_review/evaluation/offline_rag.py` | Deterministic token-hash embeddings, fixed-case chat adapter, in-memory Qdrant setup, graph trace and evaluation. |
| `src/security_review/evaluation/rag_models.py` | Validated case/result/aggregate contracts and metric denominators. |
| `src/security_review/evaluation/rag_render.py` | Stable JSON and bounded Markdown evidence rendering. |
| `scripts/run_rag_evidence.py` | Thin offline command and exit status. |
| `data/evaluation/rag_cases.json` | Fixed, labeled direct-hit/rewrite/abstain/forged-citation cases. |
| `tests/unit/evaluation/test_offline_rag.py`, `test_rag_render.py` | Adapter, manifest, trace, metrics, and output tests. |
| `tests/unit/orchestrator/test_knowledge_graph.py` | Public citation-alignment regression tests. |
| `docs/demo.md`, `docs/architecture.md`, `docs/threat-model.md`, `README.md`, `.github/workflows/ci.yml` | Reproduction, provider/test-double trust boundary, limitations, and keyless CI gate. |

---

### Task 1: Align RAG sources with answer citations

**Files:** Modify `src/security_review/orchestrator/knowledge_graph.py:107-138,261-291`; test `tests/unit/orchestrator/test_knowledge_graph.py:205-235`.

**Interfaces:** Produce `knowledge_answer_from_state(state: KnowledgeState) -> KnowledgeAnswer`; keep `KnowledgeService.answer(question: str) -> KnowledgeAnswer`. The evaluator in Task 3 consumes the helper after streaming node updates.

- [ ] **Step 1: Write failing tests.** A response citing the second of two retrieved chunks returns only that second `SourceReference`; repeated citations produce one source in first-citation order; an unknown ID still raises `KnowledgeWorkflowError("invalid_source_citation")`. Add a test that `knowledge_answer_from_state` rejects missing/invalid answer fields like `KnowledgeService.answer`.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/orchestrator/test_knowledge_graph.py -q`; expect the uncited-source assertion to fail.
- [ ] **Step 3: Implement.** In `generate_grounded_answer`, parse valid citation IDs, preserve first appearance, and return `sources` containing only referenced current chunks. Move final state validation into `knowledge_answer_from_state` and call it from `KnowledgeService.answer` without changing general/Text2SQL behavior.
- [ ] **Step 4: Run green tests.** `uv run pytest tests/unit/orchestrator/test_knowledge_graph.py -q`; expect exit 0.
- [ ] **Step 5: Commit.** `git add src/security_review/orchestrator/knowledge_graph.py tests/unit/orchestrator/test_knowledge_graph.py && git commit -m "fix: align RAG sources with citations"`.

### Task 2: Build a real keyless retrieval fixture

**Files:** Create `src/security_review/evaluation/__init__.py`, `offline_rag.py`, `rag_models.py`, `data/evaluation/rag_cases.json`, `tests/unit/evaluation/test_offline_rag.py`.

**Interfaces:** Produce `TokenHashEmbeddingModel(dimension: int = 512)` with `dimension: int` and `embed(texts: Sequence[str]) -> list[list[float]]`; `load_rag_cases(path: Path) -> tuple[RagCase, ...]`; `build_offline_retriever(document_path: Path) -> tuple[QdrantClient, QdrantDocumentRetriever, tuple[DocumentChunkInput, ...]]`. `RagCase` has `case_id`, `question`, `expected_completed_nodes`, `expected_retrieved_section` (nullable), `expected_cited_section` (nullable), `expected_outcome` (`answer`/`abstain`/`invalid_source_citation`), `rewrite_query` (nullable), and `expected_failure_stage` (nullable). A failed node is not listed among completed nodes. Task 3 owns closing the returned client.

- [ ] **Step 1: Write failing tests.** Equal texts produce equal vectors of length 512; overlapping security terms score above unrelated terms; empty/tokenless text is bounded; local Qdrant `replace_documents` followed by `search` returns a labeled section of the bundled guide. Invalid JSON, duplicate IDs, unsupported route, and oversized question fail before Qdrant creation.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/evaluation/test_offline_rag.py -q`; expect missing module/functions.
- [ ] **Step 3: Implement.** Tokenize normalized Unicode words, remove a fixed small stopword set, hash each token with SHA-256 into 512 nonnegative buckets, and return finite vectors. Use `QdrantClient(location=":memory:")`, existing loader/chunker (`chunk_size=120`, `overlap=0`), and `QdrantDocumentRetriever(min_score=0.18)`; use only original bundled material. Keep manifest cases limited to `rag` route and `max_rag_attempts=2`.
- [ ] **Step 4: Run green tests.** `uv run pytest tests/unit/evaluation/test_offline_rag.py -q`; expect exit 0 and actual local Qdrant search.
- [ ] **Step 5: Commit.** Stage only Task 2 files and commit `feat: add offline RAG retrieval fixture`.

### Task 3: Evaluate actual LangGraph paths and failure contracts

**Files:** Modify `src/security_review/evaluation/offline_rag.py`, `rag_models.py`; test `tests/unit/evaluation/test_offline_rag.py`.

**Interfaces:** Produce `run_rag_evaluation(cases_path: Path, document_path: Path) -> RagEvaluation`. Each `RagCaseResult` carries `case_id`, completed-node trace, `failure_stage` if an exception terminates a node, attempts, retrieved chunk **metadata only**, separately bounded `cited_evidence`, cited IDs, final answer/warnings or expected error, expected/actual checks. `RagEvaluation` carries case results, numerator/denominator/N/A metrics, manifest/corpus digests, `embedding_algorithm_version`, `git_revision` plus dirty/source fingerprint, and `passed: bool`.

- [ ] **Step 1: Write failing tests.** Four labels exercise direct hit, one rewrite then hit, two-search abstention, and rejected forged citation. Assert exact completed-node order; the forged case stops after `evaluate_vector_results` and records `failure_stage="grounded_answer_validation"` instead of claiming a completed generation node. Check current-attempt retrieved IDs, hit@k denominator only for retrieval labels, no source on abstention, and `passed=False` when an expected retrieved **or cited** section/path is altered. Include the counterexample where the expected section is retrieved but the adapter cites an unrelated retrieved chunk. Test unknown citations, duplicate citations, and the retry cap.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/evaluation/test_offline_rag.py -q`; expect missing evaluator or failed contract assertions.
- [ ] **Step 3: Implement.** Use one fresh deterministic `ChatModel` per case and `build_knowledge_graph(KnowledgeServices(...))`; supply `Text2SqlService` with `FakeKnowledgeRepository.empty()` as a never-called port and fail the case if it is reached. The normal adapter derives its sentence and citation ID from the graph-supplied top evidence, never from the expected-section label. Stream `updates` to collect only **completed** nodes and allowlisted fields, merge final state, and call `knowledge_answer_from_state`. For a typed graph error, compare the reason and record the validation stage separately; `updates` alone does not emit the failing node. Compute explicit numerator/denominator for path, retrieval hit@k, cited-section correctness, citation ID validity/alignment, and abstention; mark nonapplicable cases separately. Record a fixed `token-hash-v1` identifier, manifest/corpus hashes, and Git SHA plus dirty/source fingerprint. Close the in-memory Qdrant client in `finally`.
- [ ] **Step 4: Run green tests.** `uv run pytest tests/unit/evaluation/test_offline_rag.py tests/unit/orchestrator/test_knowledge_graph.py -q`; expect exit 0.
- [ ] **Step 5: Commit.** Stage Task 3 files and commit `feat: evaluate offline RAG graph contracts`.

### Task 4: Render evidence, document it, and gate it in CI

**Files:** Create `src/security_review/evaluation/rag_render.py`, `scripts/run_rag_evidence.py`, `tests/unit/evaluation/test_rag_render.py`; modify `docs/demo.md`, `docs/architecture.md`, `docs/threat-model.md`, `README.md`, `.github/workflows/ci.yml`.

**Interfaces:** `render_rag_json(evaluation: RagEvaluation) -> str`; `render_rag_markdown(evaluation: RagEvaluation) -> str`; `main(argv: Sequence[str] | None = None) -> int` writes default `build/evidence/rag.json` and `.md` and returns 1 on failed labels.

- [ ] **Step 1: Write failing tests.** Repeated evaluation renders byte-identical JSON/Markdown, excerpt length is at most 240 characters, uncited text/full raw graph state is absent, malformed output path reports a safe error, and a failed case exits nonzero. Assert both artifacts include corpus/manifest hashes, embedding version and code fingerprint. Exercise the real command in a temporary output directory and assert both artifacts exist and JSON parses; do not add tests that merely grep human prose or workflow YAML.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/evaluation/test_rag_render.py -q`; expect missing renderer/command behavior.
- [ ] **Step 3: Implement.** Render sorted-key UTF-8 JSON and escaped/bounded Markdown with excerpts only under `cited_evidence`; write files atomically as the CLI does. In CI quality, run `uv run python -m scripts.run_rag_evidence`, then separately assert both files are nonempty and parse JSON with `python -m json.tool`. Document one actual RAG question, a no-evidence case, a cited source excerpt, precise metric denominators, deterministic-adapter limitations, and provider/test-double trust boundaries in `docs/threat-model.md`.
- [ ] **Step 4: Run verification.** `uv run python -m scripts.run_rag_evidence`; inspect both files and exit 0. Review README/demo/architecture/threat-model prose and CI YAML against the spec manually. Then run `uv run pytest tests/unit/evaluation tests/unit/orchestrator/test_knowledge_graph.py tests/unit/docs -q`, `uv run ruff check src/security_review/evaluation scripts/run_rag_evidence.py`, and `uv run mypy src scripts/run_rag_evidence.py`; expect all exit 0.
- [ ] **Step 5: Commit.** Stage Task 4 files and commit `docs: publish reproducible offline RAG evidence`.

## End-of-plan gate

Run `uv run pytest tests/unit tests/e2e -q`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src apps`, and `uv run bandit -q -r src apps`; record actual output, not assumed success. Review the branch diff for raw secrets and unintended provider calls. The scanner plan may subsequently edit shared README/docs/CI files; reconcile those changes before the final combined test and GitHub push.
