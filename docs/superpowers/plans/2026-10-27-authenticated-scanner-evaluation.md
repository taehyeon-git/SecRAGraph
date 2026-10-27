# Authenticated Scanner Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce reproducible, credential-free published evidence for all fixed scanner cases through member login and the live API.

**Architecture:** A pure HTTP evaluator reuses existing case assessment math; an isolated Compose runner creates members, invokes the evaluator, and cleans up. README and a dated evidence note report the observed result only after a real run.

**Tech Stack:** Python 3.11, FastAPI, httpx, PostgreSQL, Docker Compose, pytest.

**Spec:** `docs/superpowers/specs/2026-10-27-authenticated-scanner-evaluation.md`

## Global Constraints

- Do not hardcode the current 53 cases as an evaluator limit.
- Keep all credentials, tokens, raw case source, and report UUIDs out of artifacts and error output.
- Use one-file ZIP uploads to preserve nested paths and `.env`; disable automatic CWE/OSV in the isolated stack.
- Fail the command on incomplete coverage or mismatched findings; label the synthetic corpus honestly.

## Review Focus

- A nested path or `.env` case must retain its exact path in the returned finding.
- Authentication must be tested before and after login, across members, and after logout.
- An upload response and persisted report must agree before its finding is scored.
- Network/API failure must fail without publishing a partial artifact or secret.
- Compose startup failure must still remove the isolated project and volumes.

---

### Task 1: Authenticated HTTP evaluator

**Files:** `src/security_review/evaluation/authenticated_scanner.py`, `src/security_review/evaluation/scanner_benchmark.py`, `tests/unit/evaluation/test_authenticated_scanner.py`

**Interface:** `run_authenticated_scanner_benchmark(client: httpx.Client, cases_path: Path, *, username: str, password: str, second_username: str, second_password: str) -> AuthenticatedScannerResult`; result exposes `.benchmark`, safe counts and `.to_json()` / `.to_markdown()`.

- [ ] Write tests for member login, one-file ZIP path fidelity, persisted report parity, scoring, unauthorized/foreign/logout denial, and sanitized failures.
- [ ] Run those tests and observe expected failures before implementation.
- [ ] Implement the evaluator using `load_scanner_cases`, `assess_scanner_case`, and `score_findings`.
- [ ] Run focused tests, Ruff, and mypy; review returned evidence fields for sensitive data.

### Task 2: Isolated Compose runner

**Files:** `scripts/run_authenticated_scanner_benchmark.py`, `tests/unit/scripts/test_authenticated_scanner_benchmark.py`

**Consumes:** Task 1 interface and existing `scripts/compose_smoke.py` port/member/Compose helpers.

- [ ] Write tests for isolated ports, random credentials, disabled optional fetches, artifact publication, sanitized failures, and cleanup.
- [ ] Run those tests and observe expected failures before implementation.
- [ ] Implement a one-command runner that starts Compose, creates two members, invokes Task 1, writes safe artifacts, and always tears down.
- [ ] Run focused tests, Ruff, and mypy.

### Task 3: Real evaluation and portfolio evidence

**Files:** `README.md`, `docs/evidence/authenticated-scanner-2026-10-27.md`, `docs/demo.md`, relevant documentation tests.

- [ ] Commit Tasks 1–2 and this spec/plan, then verify the worktree is clean so the evaluator's `current_revision` names the code actually built by Compose.
- [ ] Run the one-command Compose evaluation against the current full case manifest and inspect the safe JSON/Markdown outputs.
- [ ] Compare its corpus hash, rule version, TP/FP/FN, diagnostic counts, and coverage to the local evaluation; investigate any mismatch before writing claims.
- [ ] Add the authenticated API row and execution boundary to README, plus a dated evidence note with reproduction and limitations.
- [ ] Run documentation tests, the relevant full test suite, Ruff, mypy, Bandit, and `git diff --check`.
- [ ] Commit, push a PR, review CI, and merge into `main` after all required checks pass.
