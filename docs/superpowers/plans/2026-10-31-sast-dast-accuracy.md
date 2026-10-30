# SAST and DAST Accuracy Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the three measured misses and add bounded, reportable Python cross-file source-to-sink tracing without claiming universal coverage.

**Architecture:** Keep the stable Opengrep adapter and ZAP results intact. Add an independent `python-flow` SAST result and an independently attributed differential DAST result, then reconcile benchmark labels, API evidence, CI gates, and documentation.

**Tech Stack:** Python 3.11 AST, FastAPI/LangGraph report models, pinned Opengrep 1.32, pinned ZAP Docker image, pytest, Docker Compose.

**Spec:** `docs/design/accuracy-upgrade-2026-10-31.md`

## Global Constraints

- Never import or execute uploaded source; read only validated bounded snapshots.
- Never send active DAST probes to arbitrary URLs or unapproved containers.
- Preserve source-free findings, bounded time/size, explicit partial coverage, and independent engine identities.
- Keep CodeQL confined to the public repository self-scan.

## Review Focus

- An import path escapes the snapshot or a symlink redirects a cross-file read.
- A benign int conversion or parameterized query is reported as injection.
- A source/sink trace claims a file or line that was not proven by the analyzer.
- Response instability or a redirect makes a DAST differential probe falsely positive.
- A CI gate is weakened by changed rule IDs or benchmark denominators.

---

### Task 1: Existing Opengrep rule errors

**Files:** `data/engines/opengrep/**`, `src/security_review/scanner/opengrep_adapter.py`, `data/evaluation/multiengine_cases.json`, scanner tests, `docs/evidence/multiengine-scanner-2026-10-27.md`.

- [ ] Reproduce exact shell-pattern FP and f-string SQL FN with the pinned engine.
- [ ] Add vulnerable and benign tests that fail for the intended reason.
- [ ] Patch the SQL rule; retain broad shell coverage while excluding only AST-proven numeric f-string arguments. Update provenance hashes and verify the old labels plus new cases.
- [ ] Run the authored and pinned external challenge; record both scores and remaining misses.

### Task 2: Conservative Python cross-file SAST

**Files:** create `src/security_review/scanner/python_flow.py`, `tests/unit/scanner/test_python_flow.py`; modify `src/security_review/application.py`, `data/evaluation/multiengine_cases.json`.

- [ ] Add failing tests for a real static import chain, source/step/sink locations, benign controls, unsupported imports, time/size limits, and source redaction.
- [ ] Implement AST-only bounded propagation and a distinct `python-flow` execution record.
- [ ] Add authored cross-file benchmark cases with exact rule/file/line/trace expectations.
- [ ] Verify API and CLI report rendering and the authored corpus with the pinned scanner stack.

### Task 3: Numeric SQL DAST blind spot

**Files:** `src/security_review/dast/*`, `src/security_review/evaluation/dast_benchmark.py`, `scripts/run_dast_evidence.py`, `data/evaluation/dast_cases.json`, corresponding tests and `docs/evidence/dast-benchmark.md`.

- [ ] Reproduce ZAP's missing alert for the numeric vulnerable route and confirm the safe route.
- [ ] Add failing differential-probe tests including instability, redirects, bounds, auth and cleanup.
- [ ] Implement a separately attributed rule; never label it `ZAP/40018`.
- [ ] Run the disposable Docker fixture and update rule-specific and total benchmark evidence without erasing the ZAP-only baseline.

### Task 4: Evidence and documentation integration

**Files:** `scripts/compose_smoke.py`, `scripts/aggregate_pipeline_benchmark.py`, their tests, `README.md`, `docs/architecture.md`, `docs/demo.md`, CI workflow as needed.

- [ ] Update exact expected engine contracts and add tests that fail when the new engine is absent or incomplete.
- [ ] Validate JSON/Markdown/SARIF trace and finding identity, aggregate benchmark schema, and CI gates.
- [ ] Document measured before/after data and supported boundaries; remove stale claims of an unresolved fixed case.
- [ ] Run focused and full tests, Ruff/mypy/Bandit, Docker benchmarks, PR CI, then merge and verify main artifacts.
