# Expanded Scanner Corpus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a broader, reproducible scanner evaluation through local and member-authenticated API paths while preserving older evidence.

**Architecture:** Archive the original manifest and append independently labelled cases to the strict current manifest. Fix per-rule denominator accounting, run both evaluators on a clean committed revision, then publish a dated result and refresh current-state documentation.

**Tech Stack:** Python 3.11, pytest, FastAPI, Docker Compose, PostgreSQL, Qdrant, Markdown.

**Spec:** `docs/superpowers/specs/2026-10-27-expanded-scanner-corpus.md`

## Global Constraints

- Keep the original 53-case snapshot and dated 39/53 evidence intact.
- Do not turn unsupported unsafe patterns into benign labels or silently drop failing candidates.
- Keep exact case/rule/line scoring and nonzero exits for unexpected/missing findings.
- Do not put raw source, temporary member credentials, tokens, or report UUIDs in public evidence.
- Commit evaluation code and manifest before the authenticated run so the recorded revision identifies the built scanner.

## Review Focus

- All nine supported file extensions must appear in the active corpus.
- A benign file outside a rule's extension set must not dilute that rule's false alarm denominator.
- Multi-finding cases must be counted by distinct `(case ID, rule ID, line)` labels, including two rules on one file.
- Historical 53-case inputs must remain unchanged and independently reproducible.
- Local and authenticated API assessments must match case by case; all temporary Compose resources must be removed.

---

### Task 1: Corpus breadth and historical integrity

**Files:** `data/evaluation/scanner_cases.json`, `data/evaluation/history/scanner_cases_53_2026-10-27.json`, `tests/unit/evaluation/test_scanner_benchmark.py`, `tests/unit/intelligence/test_dynamic_cwe.py`.

- [ ] Copy the current manifest to history and verify its normalized SHA-256 equals `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826`.
- [ ] Point the prior dated authenticated evidence note's input path at the archived snapshot, without changing its numbers or archived outputs.
- [ ] Write failing dimension and historical-preservation tests. Remove the old assumption that every new positive has exactly one label and a paired negative.
- [ ] Merge vetted Python and non-Python candidates into the active manifest with semantic expected labels; validate unique IDs, paths, syntax, and supported extensions.
- [ ] Run the strict local benchmark. Investigate each mismatch rather than selecting only easy passing cases; add scanner regression tests and the smallest justified fix when a supported behavior is defective.
- [ ] If scanner detection behavior changes, bump `RULE_SET_VERSION` in `src/security_review/reporting/builder.py` and update its tests.
- [ ] Freeze the new corpus hash, totals, label counts and by-rule metrics in the command test only after a clean run.

### Task 2: Accurate per-rule benign denominator

**Files:** `src/security_review/evaluation/scanner_benchmark.py`, `tests/unit/evaluation/test_rule_benign_denominators.py`.

- [ ] Demonstrate with a failing test that a `.yaml` benign case currently dilutes a Python-only rule's benign denominator.
- [ ] Restrict each rule's eligible benign set to files that rule can scan while leaving overall denominator unchanged.
- [ ] Run focused tests, Ruff, mypy, and the expanded benchmark.

### Task 3: Live measurement and documentation

**Files:** `README.md`, `docs/demo.md`, `docs/architecture.md`, `docs/operations.md`, `docs/official-corpus.md`, a new dated note and sanitized JSON/Markdown under `docs/evidence/`.

- [ ] Independently review corpus labels and scorer changes, then commit all implementation changes and verify a clean worktree.
- [ ] Run the local benchmark and isolated member-authenticated Compose benchmark at the committed revision; compare corpus hash, rule version, coverage, metrics, and case records.
- [ ] Save sanitized outputs and hashes; state actual measured denominators, skips, diagnostics, limits, and unchanged historical results.
- [ ] Update current-state README/demo and supporting docs, keeping dated old snapshots historical.
- [ ] Run documentation tests, full pytest with isolated PostgreSQL/Qdrant/API, Ruff, mypy, Bandit, and `git diff --check`.
- [ ] Push a PR, check all CI, use a merge commit so the measured implementation SHA stays in `main` history, and verify post-merge CI.
