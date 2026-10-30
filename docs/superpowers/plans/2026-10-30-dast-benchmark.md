# DAST Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reproducible eight-case DAST regression benchmark and improve the pipeline based on its measured baseline.

**Architecture:** One disposable fixture supplies eight labelled vulnerable/benign GET cases. The existing passive and active ZAP reports feed a pure manifest scorer; the evidence script verifies coverage and writes benchmark artifacts only after successful teardown.

**Tech Stack:** Python 3.11, FastAPI/SQLite, pinned OWASP ZAP API scan, Docker Compose, pytest, GitHub Actions.

**Spec:** [Disposable API DAST benchmark](../../design/dast-benchmark.md).

**Independent design review (2026-10-30):** Approved after resolving four issues: detection assertions move into scored results, three fixture snapshots prove phase-specific coverage, active seeds and scope derive from the manifest, and unassessed counts explicitly cover normalized alerts only. Pull requests print bounded benchmark metrics even though normalized artifacts are uploaded only from trusted main.

## Global constraints

- Keep active DAST's full Docker ID, two labels, marked GET seeds, isolated network and opt-in CLI unchanged.
- Never store raw HTTP bodies, query payloads, temporary tokens or raw ZAP JSON in benchmark artifacts.
- Score only exact manifest rule/path pairs with separately verified coverage; unvisited or incomplete cases are unscored failures.
- Preserve existing six normalized DAST reports; move SQLi/header detection gates into the benchmark score while retaining completion, isolation, seed and probe gates.
- Baseline and final metrics must use the same manifest SHA-256; disclose author-written case limits.

## Task 1: Labelled fixture and manifest

**Files:** `apps/dast_fixture/main.py`, `data/evaluation/dast_cases.json`, fixture tests, `infra/dast/compose.yaml` only if required.

- [ ] Write failing tests for numeric SQLi vulnerable/benign behavior, external redirect vulnerable/benign behavior, OpenAPI active annotations and privacy-safe per-route request/probe counters.
- [ ] Add exactly eight manifest cases: four SQLi, two redirect and two header, with stable IDs, rule IDs, expected values, modes and proof types.
- [ ] Implement fixture routes and counts without changing old endpoint semantics; run focused tests, Ruff, mypy and Bandit; commit.

## Task 2: Pure benchmark evaluator

**Files:** `src/security_review/evaluation/dast_benchmark.py`, `tests/unit/evaluation/test_dast_benchmark.py`.

- [ ] Write failing tests for manifest validation, exact rule/path scoring, per-case probe delta, missing/incomplete coverage refusal, unassessed finding count, zero-denominator metrics and payload-free rendering.
- [ ] Implement loader/scorer and JSON/Markdown output. Return immutable results with per-rule and aggregate TP/FP/FN/TN, manifest SHA and timings supplied by caller; commit after focused tests/Ruff/mypy.

## Task 3: Pipeline and live baseline

**Files:** `scripts/run_dast_evidence.py`, `.github/workflows/ci.yml`, script tests and documentation.

- [ ] Add failing integration tests for three fixture stats snapshots, manifest-derived active seed set and report paths, benchmark publication after teardown, incomplete-scan refusal and CI artifact contract.
- [ ] Wire scorer to the same passive/active reports and manifest, capture fixture image ID/source revision and wall time, retain non-detection gates, publish `dast-benchmark.json/md`; run unit/static checks and commit. Print aggregate metrics in PR CI logs while uploading normalized artifacts only on trusted main.
- [ ] Run real Docker ZAP against the new fixed manifest, record baseline metrics and SHA. Analyze misses/false positives before making a scanner improvement.

## Task 4: Result-based improvement, review and merge

- [ ] Add a failing regression test for the measured gap, apply the smallest defensible scanner/orchestration fix without editing labels, rerun the same live benchmark and compare.
- [ ] Write `docs/evidence/dast-benchmark.md` with baseline/final exact denominators, run commands, manifest hash, tool/fixture identity, timings and limitations; update README/demo.
- [ ] Independently review security boundaries and evaluation honesty; run full relevant tests and static checks; push PR.
- [ ] Require protected CI and CodeQL checks, inspect `main` benchmark artifact, merge and verify `main` CI.
