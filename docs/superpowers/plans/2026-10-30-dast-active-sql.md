# Active API DAST Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicitly authorized, bounded ZAP active API scan and prove SQL injection detection against a disposable fixture in CI.

**Architecture:** Reuse the Docker-isolated DAST runner with an `active` flag and filtered marked GET OpenAPI routes. Keep passive and active reports separate while using the same LangGraph normalization.

**Tech Stack:** Python 3.11, FastAPI, SQLite, Docker Engine isolated bridge, digest-pinned OWASP ZAP API scan, pytest, GitHub Actions.

**Spec:** [Bounded active API DAST](../../design/dast-active-sql.md).

## Global Constraints

- Passive mode remains the CLI default and retains existing report behavior.
- Active mode requires explicit CLI flag, two Docker labels, full immutable container ID and marked GET routes.
- Keep raw ZAP requests/responses, query values and credentials out of normalized artifacts.
- No member-upload or arbitrary-URL DAST trigger; fail closed on incomplete scan or cleanup.

## Review Focus

- Missing or renamed target after inspect must not redirect the active scan to a different container.
- OpenAPI server override or unmarked route must not enter active seeds.
- Packaged ZAP may return report data without actually finishing active scan; marker must be verified.
- ZAP alert path/query or raw payload must not leak into normalized reports.
- An active finding from a different route must not be counted as the fixture's SQLi proof.

---

### Task 1: Active runner and public CLI

**Files:** `src/security_review/dast/runner.py`, `src/security_review/dast/zap.py`, `src/security_review/dast/application.py`, `src/security_review/cli.py`; corresponding tests in `tests/unit/dast/` and `tests/unit/cli/test_dast.py`.

**Interfaces:** Add `active: bool = False` to `run_zap_api_scan`, `scan_dast_container` and CLI service. `sanitize_openapi(raw, *, origin, active=False)` filters marked GET operations in active mode.

- [ ] Add failing tests for both labels, full ID, marked routes, active ZAP command, hook completion marker, mode-specific coverage/warnings and CLI flag.
- [ ] Run focused tests and record expected failures.
- [ ] Implement only the tested active path; keep passive behavior and bounded cleanup.
- [ ] Run focused tests, Ruff and mypy; commit.

### Task 2: Disposable fixture and evidence gate

**Files:** `apps/dast_fixture/main.py`, `infra/dast/compose.yaml`, `scripts/run_dast_evidence.py`, `.github/workflows/ci.yml`, `.github/codeql/codeql-config.yml`, fixture/evidence tests.

**Interfaces:** `scan_dast_container(..., active=True)` returns a completed active report. `run_dast_evidence` writes `dast-active.{json,md,sarif}` only after both scans pass their gates.

- [ ] Add failing fixture tests for injectable and parameterized GET queries, mutated request counts, and active evidence gate tests for expected `ZAP/40018`/`CWE-89` only on vulnerable route.
- [ ] Run focused tests and record expected failures.
- [ ] Implement fixture, CI gate, artifact contract, and docs updates.
- [ ] Run focused tests, Ruff, mypy, and isolated live CI; commit.

### Task 3: Integration review

**Files:** README, `docs/demo.md`, `docs/design/dast-isolated-api.md`, `docs/design/dast-active-sql.md`.

- [ ] Review exact diff for target authorization, request containment, evidence completeness, docs honesty and old passive path.
- [ ] Run full relevant test suite and static checks; push PR.
- [ ] Require all nine protected checks, inspect live active evidence, merge to main, and verify main CI artifact.
