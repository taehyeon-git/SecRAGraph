# Multi-engine Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace eight project-authored rules with specialized, coverage-aware security engines and evidence-based evaluation.

**Architecture:** Public CI runs CodeQL `security-extended`. Member uploads run Opengrep with MIT rules, Gitleaks, Checkov, and existing OSV on a bounded safe snapshot; LangGraph merges findings and coverage into one report. Evaluation separates labeled accuracy from unlabeled operational measurements.

**Tech Stack:** Python 3.11, FastAPI, LangGraph, Opengrep, Gitleaks, Checkov, OSV, CodeQL Actions, PostgreSQL, SARIF 2.1.0.

**Spec:** `docs/superpowers/specs/2026-10-27-multiengine-scanner.md`

## Global Constraints

- CodeQL free license is only used in the public GitHub repository CI, never for member uploads.
- Target source is never built or executed; only accepted UTF-8 files enter external scanners.
- Secret values, source snippets, and subprocess logs are never persisted.
- A missing/failed/timed-out engine is not a clean scan.
- Existing 120-case result is historical regression evidence, not general detection accuracy.

## Review Focus

- A target-supplied `.semgrep.yml`, `.checkov.yaml`, or `.gitleaks.toml` cannot change scanner behavior: adapter tests use a hostile config fixture and assert trusted options.
- A symlink or changed file cannot enter a snapshot: snapshot test checks the rejection and resulting path list.
- A nonzero subprocess exit with JSON findings cannot become `completed`: adapter tests assert partial/error coverage.
- Raw secret strings cannot survive normalization: tests inspect JSON/Markdown/SARIF and DB mapping.
- Unlabeled repositories cannot have TP/FP/FN: evaluator test asserts those fields are absent or null.

---

### Task 1: Report and persistence contract

**Files:** `src/security_review/domain/models.py`, `src/security_review/reporting/{builder,markdown,sarif}.py`, `src/security_review/storage/models.py`, `migrations/versions/*`, focused tests.

**Interfaces:** `ScanExecution(engine,kind,status,version,elapsed_ms,eligible_files,scanned_files,languages,checks,reason)`, `TraceLocation(file_path,line_start,line_end,role)`, `Finding.engine/trace`, `ScanReport.executions`.

- [ ] Add failing tests for path validation, text-free traces, all four statuses, and report renderers.
- [ ] Run focused tests and confirm the expected failure.
- [ ] Implement models and renderers, preserving old report fixtures with default empty executions.
- [ ] Add DB migration and round-trip tests.
- [ ] Run focused tests and commit.

### Task 2: Safe snapshot and SAST adapter

**Files:** `src/security_review/scanner/{files,snapshot,opengrep_adapter}.py`, `src/security_review/application.py`, `data/engines/opengrep-rules/*`, focused tests.

**Interfaces:** `safe_snapshot(discovery,limits)->context manager Snapshot` and `OpengrepAdapter.scan_snapshot(root,timeout)->ExternalScanResult`.

- [ ] Add failing tests for supported language/config extensions, symlinks, tool absence, SARIF normalization and source-to-sink paths.
- [ ] Run focused tests to confirm failure.
- [ ] Implement snapshot and Opengrep adapter with pinned MIT rules, trusted config, and timeout.
- [ ] Run focused tests and commit.

### Task 3: Dedicated secret and configuration engines

**Files:** `src/security_review/scanner/external_detectors.py`, `Dockerfile`, `compose.yaml`, focused tests.

**Interfaces:** `GitleaksAdapter.scan_snapshot(root,timeout)` and `CheckovAdapter.scan_snapshot(root,timeout)` return `ExternalScanResult`.

- [ ] Add failing tests for redaction, hostile config, timeout/error, and missing binary.
- [ ] Run focused tests to confirm failure.
- [ ] Implement adapters and pinned runtime installation without remote target downloads.
- [ ] Run focused tests and container smoke; commit.

### Task 4: Graph, OSV, and report integration

**Files:** `src/security_review/orchestrator/scan_graph.py`, `src/security_review/application.py`, `src/security_review/reporting/builder.py`, `src/security_review/storage/models.py`, migration, focused API/CLI/storage tests.

**Interfaces:** `DeterministicScanResult.executions`, `ScanState.executions`, report builder `executions=`; dependency auditor adds OSV execution coverage.

- [ ] Add failing scan lifecycle tests with one engine unavailable and another finding.
- [ ] Run focused tests to confirm failure.
- [ ] Merge dedicated engine results, OSV coverage, and warnings through LangGraph into all report formats.
- [ ] Run API/CLI/storage focused tests and commit.

### Task 5: Public CodeQL flow and removal of old rules

**Files:** `.github/workflows/security-scan.yml`, `codeql/*`, `src/security_review/scanner/{rules,engine,python_calls,node_tls}.py` (delete), `src/security_review/intelligence/case_corpus.py`, tests.

**Interfaces:** CodeQL Actions `queries: security-extended`; CWE case selection no longer imports deleted rules.

- [ ] Add failing workflow contract/CodeQL fixture tests and run them.
- [ ] Add CodeQL workflow and safe source/sink/barrier model fixture.
- [ ] Remove active eight-rule scanner and refactor direct imports/evaluation to new engines.
- [ ] Run CodeQL fixture and Python tests; commit.

### Task 6: Evaluation and documentation

**Files:** `src/security_review/evaluation/*`, `scripts/run_*benchmark.py`, `data/evaluation/*`, `README.md`, `docs/demo.md`, focused tests.

**Interfaces:** labeled-case evaluation yields per-engine/per-rule TP/FP/FN with denominators and elapsed time; unlabeled-real evaluation emits coverage/hits/time only.

- [ ] Add failing tests distinguishing regression, labeled external, and unlabeled real runs.
- [ ] Run focused tests to confirm failure.
- [ ] Expand positive and benign fixtures; record immutable external inputs and per-rule numbers.
- [ ] Run integration, benchmark, type/lint, CI checks and update README with measured results and limitations.
- [ ] Independently review the diff, repair issues, rerun verification, then commit and merge to main.
