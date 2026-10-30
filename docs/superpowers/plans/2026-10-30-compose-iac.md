# Docker Compose IaC Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect explicit high-risk Docker Compose declarations in API, CLI and LangGraph scans without executing a Compose file or claiming an effective deployment configuration.

**Architecture:** A dedicated `compose-policy` adapter reads bounded snapshot YAML nodes and returns the existing `Finding`/`ExternalScanResult` contract. The application adds one configuration-engine execution; Checkov receives a filtered private staging tree so Compose files never become false Checkov coverage. Existing multi-engine evaluation scores only completed single-file Compose cases.

**Tech Stack:** Python 3.11, PyYAML 6.0.3 (direct locked dependency), Pydantic domain models, pytest, Ruff, mypy, Docker-isolated CI benchmark.

**Spec:** [Compose IaC design](../../design/compose-iac.md)

## Global Constraints

- Keep the target inert: do not call Docker/Compose, read `env_file`/`include`/bind sources, interpolate variables, execute shell, or fetch network data.
- Recognize only the case-insensitive `compose.yml`/`.yaml`, `docker-compose.yml`/`.yaml` and `compose.*`/`docker-compose.*` YAML basenames specified by the design. Do not infer arbitrary `-f` files.
- Fixed policy version `2026.10.30.1`, engine `compose-policy`, rule IDs `COMPOSE/<RULE>`, unique deterministic hashed `Finding.id`, kind/category `configuration`.
- Per adapter: at most 1 MiB/file, 20 MiB total, 500 candidate files, 10,000 YAML nodes/file, nesting depth 64, 2,000 findings, and the supplied scan deadline.
- Report fixed messages/evidence and stable reason codes only; never copy YAML values, service names or snippets into findings/warnings. Findings describe **declared** settings, not merged or active deployment state.
- Map only reviewed privilege rules to CWE-250, leave other CWE IDs empty, and never infer a CVE from a Compose setting.
- Any aliases/anchors, merge keys, duplicate keys, custom tags, unsupported syntax, dynamic inspected values or external references prevent a `completed` claim. Multiple recognized Compose files in the same directory are `partial` because their effective override configuration is unresolved; files in different directories are independent candidates. Preserve independently confirmed literal findings in a `partial` execution.
- Benchmark labels for `compose-policy` belong only to single-file `completed` cases. Partial cases stay in unit/integration coverage tests; authored scores are regression evidence, not field accuracy.

## File Map and Agent Boundaries

| Owner | Files | Responsibility |
| --- | --- | --- |
| Foundation | `src/security_review/scanner/compose_files.py`, `tests/unit/scanner/test_compose_files.py`, `pyproject.toml`, `uv.lock` | One shared filename predicate and direct locked YAML dependency. |
| Policy | `src/security_review/scanner/compose_adapter.py`, `tests/unit/scanner/test_compose_adapter.py` | Bounded node parsing, ten literal policies and honest per-file coverage. |
| Pipeline | `src/security_review/application.py`, `src/security_review/scanner/external_detectors.py`, `tests/unit/scanner/test_pipeline.py`, `tests/unit/scanner/test_external_detectors.py` | Fourth execution, Checkov filtered scan root and path verification. |
| Evidence | `data/evaluation/multiengine_cases.json`, `scripts/check_compose_evidence.py`, `tests/unit/scripts/test_check_compose_evidence.py`, `.github/workflows/ci.yml`, `README.md`, `docs/architecture.md`, `docs/demo.md`, `docs/evidence/compose-iac-2026-10-30.md` | Completed labels, Compose-only quality gate, measured results and limits. |

Foundation completes first. Policy and Pipeline can work concurrently against the interfaces below; the integrator runs their combined tests before Evidence starts. Agents do not edit each other's listed files.

## Review Focus

1. A `compose.yaml` containing both a confirmed literal risk and `include` must retain the finding while its execution is `partial` — Task 2 test.
2. A `compose.yaml` plus `compose.override.yaml` in the same directory may override a declaration; both files are inspected but effective configuration is unresolved. Compose files in different directories do not trigger that reason — Task 2 tests.
3. A path such as `docker-compose.override.yaml` must never be sent to Checkov even though its extension is YAML — Task 3 test.
4. An absolute Checkov result path under the original snapshot must be rejected after filtered staging; a path under the staged tree must map back to the original relative file — Task 3 test.
5. A YAML alias or duplicate mapping key cannot be silently ignored to produce `completed` — Task 2 tests.

---

### Task 1: Shared recognition and locked dependency

**Files:** Create `src/security_review/scanner/compose_files.py`; create `tests/unit/scanner/test_compose_files.py`; modify `pyproject.toml` and `uv.lock`.

**Interfaces:** Produce `is_compose_file(path: str) -> bool` and `COMPOSE_POLICY_VERSION = "2026.10.30.1"`. The predicate inspects a POSIX relative path's basename only. Tasks 2 and 3 import it; neither copies its regex.

- [ ] **Step 1:** Write parameterized failing tests: `compose.yaml`, `Docker-Compose.yml`, `compose.override.yaml`, `docker-compose.test.yml` and `compose..yaml` are true under the design's ASCII suffix grammar; `other.yaml`, `compose.env`, `compose.한글.yml` and `not-compose.yaml` are false.
- [ ] **Step 2:** Run `uv run pytest tests/unit/scanner/test_compose_files.py -q`; confirm expected import/assertion failure.
- [ ] **Step 3:** Implement the predicate with the exact design basename grammar. Add `pyyaml==6.0.3` as a direct dependency and regenerate the lock with `uv lock`.
- [ ] **Step 4:** Run `uv lock --check`, `uv run pytest tests/unit/scanner/test_compose_files.py -q`, `uv run ruff check src/security_review/scanner/compose_files.py tests/unit/scanner/test_compose_files.py`, and `uv run mypy src/security_review/scanner/compose_files.py`; all pass.
- [ ] **Step 5:** Commit only this task's files after review.

### Task 2: Bounded Compose parser and ten policy rules

**Files:** Create `src/security_review/scanner/compose_adapter.py`; create `tests/unit/scanner/test_compose_adapter.py`.

**Interfaces:** Consume `is_compose_file(path: str) -> bool` and `COMPOSE_POLICY_VERSION` from Task 1. Produce `ComposePolicyAdapter.scan_snapshot(root: Path, timeout: float) -> ExternalScanResult` with `execution.scanner == "compose-policy"`. The adapter uses `_snapshot_files` or equivalent link-safe enumeration, returns `eligible_files`, `inspected_files`, rule IDs in `checks`, fixed reason codes and source-line `Finding` records; it never calls a subprocess.

- [ ] **Step 1:** Write failing table tests with one recognized file per test and exact rule/line/severity assertions for `PRIVILEGED`, `HOST_NETWORK`, `HOST_PID`, `HOST_IPC`, `CAP_ADD_DANGEROUS`, `UNCONFINED_PROFILE`, `DOCKER_SOCKET`, `HOST_ROOT_MOUNT`, `EXPLICIT_ROOT_USER` and `PROVIDER`. Cover both `SYS_ADMIN` and `CAP_SYS_ADMIN`, short and long bind forms, read-only Docker socket, `seccomp=unconfined`/`apparmor:unconfined`, `root:<group>` and `0:<group>`, flow-style YAML, comments and quoted scalars. Assert ordinary named volumes, project bind mounts, nonroot users, `privileged: false` and missing `read_only` produce no finding.
- [ ] **Step 2:** Run `uv run pytest tests/unit/scanner/test_compose_adapter.py -q`; confirm failure because the adapter is absent.
- [ ] **Step 3:** Implement bounded PyYAML event/node parsing and rule evaluation. Preflight byte size and detect anchors/aliases in events before composing nodes; under `timeout` reject duplicate keys, merge keys, custom tags, multiple documents, cycles, >10,000 nodes or depth >64. Walk only a top-level `services` mapping and explicit service fields. Use node marks for 1-based lines, preserve scalar type/quoting, treat dynamic inspected values and `include`/`extends` as partial, and use fixed redacted text. `eligible_files` includes recognized files; `inspected_files` includes only files whose explicit service fields were checked. Keep confirmed literal findings even on a partial file.
- [ ] **Step 4:** Add failing abuse/coverage tests for invalid UTF-8/binary, malformed or unsupported top-level YAML, oversized file, >500 files, >20 MiB total, >2,000 findings, node/depth cap, deadline, alias/merge/duplicate/custom tag, dynamic `${...}` and include/extends. Assert `effective_config_not_resolved` for two recognized files in one directory, but not for files in different directories. Assert no source value in serialized results and deterministic IDs. Use monkeypatch to prove `subprocess`/network/file-reference paths are never called.
- [ ] **Step 5:** Run `uv run pytest tests/unit/scanner/test_compose_adapter.py -q`, `uv run ruff format --check src/security_review/scanner/compose_adapter.py tests/unit/scanner/test_compose_adapter.py`, `uv run ruff check ...`, and `uv run mypy src/security_review/scanner/compose_adapter.py`; all pass.
- [ ] **Step 6:** Commit only this task's files after review.

### Task 3: Pipeline integration and Checkov input isolation

**Files:** Modify `src/security_review/application.py`, `src/security_review/scanner/external_detectors.py`, `tests/unit/scanner/test_pipeline.py`, `tests/unit/scanner/test_external_detectors.py`.

**Interfaces:** Consume Tasks 1 and 2. Extend `_deterministic_scan(..., compose_adapter: _SnapshotAdapter | None = None)`, `_eligible_snapshot_files("compose-policy", paths)`, `_execution_record` and `_language_for_path` to output one `configuration` execution with language `docker-compose`. Set an explicit `compose-policy` engine time budget of 20 seconds. `CheckovAdapter.scan_snapshot` still reports original relative paths, but runs Checkov against a filtered staging root.

- [ ] **Step 1:** Write failing pipeline tests: a single Compose target yields four executions in order `opengrep`, `gitleaks`, `checkov`, `compose-policy`; Checkov is skipped, Compose is completed, language is `docker-compose`, and findings survive LangGraph/report serialization. A deadline-expired request shows Compose's eligible file and `not_run` status.
- [ ] **Step 2:** Write failing Checkov mock tests where the source snapshot has `main.tf` and `docker-compose.override.yaml`. Assert `--directory` points to a private staging tree containing only `main.tf`; a report's staged absolute path normalizes to `main.tf`, while a report path under the original snapshot or a Compose path is rejected. Update existing mocks that currently return original-root absolute paths.
- [ ] **Step 3:** Run `uv run pytest tests/unit/scanner/test_pipeline.py tests/unit/scanner/test_external_detectors.py -q`; confirm the new tests fail for the intended missing behavior.
- [ ] **Step 4:** Implement fourth-engine registration, Checkov predicate exclusion and bounded copy of verified non-Compose eligible files into `work_dir/input`, a private staging tree separate from `trusted.yaml`. Reject links and stage over 500 files/20 MiB; count staging against the existing Checkov deadline. Pass the staged root to both `--directory` and `_parse_checkov(payload, staged_root, eligible, frameworks)`; keep report locations original-relative.
- [ ] **Step 5:** Run the two unit files, `uv run pytest tests/e2e/test_cli.py -q`, Ruff format/check on modified Python and `uv run mypy src/security_review/application.py src/security_review/scanner/external_detectors.py`; all pass.
- [ ] **Step 6:** Commit only this task's files after review.

### Task 4: Scored evaluation and truthful documentation

**Files:** Modify `data/evaluation/multiengine_cases.json`, `.github/workflows/ci.yml`, `README.md`, `docs/architecture.md`, `docs/demo.md`; create `scripts/check_compose_evidence.py`, `tests/unit/scripts/test_check_compose_evidence.py`, `docs/evidence/compose-iac-2026-10-30.md`.

**Interfaces:** Consume Task 3's `compose-policy` engine and the existing `scripts.run_multiengine_benchmark`. No benchmark runner API change is expected. The authoring manifest remains schema version 1; each new case has exactly one recognized Compose file so its execution can be scored.

- [ ] **Step 1:** Add ten one-file positive cases, each assessing all ten `COMPOSE/*` rules with the named rule positive and the others negative, plus one benign one-file control assessing all ten negative. Include `:ro` socket and root-group variants in focused cases. Keep dynamic/malformed/multi-file partial examples in Task 2/3 tests, not this CI-scored manifest.
- [ ] **Step 2:** Run the existing corpus benchmark in a prepared scanner runtime with `--require-complete --require-traces` (the existing corpus has known FP/FN and cannot pass global `--require-match`). Add a tested `scripts.check_compose_evidence` step after the JSON evidence in CI: require all ten expected Compose rule IDs, at least one positive per rule, every Compose assessment scored, and Compose-only FP=FN=0. Record per-rule TP/FP/FN, execution times, manifest SHA-256 and version from the actual run. If local external tools are unavailable, use the pinned CI runtime's result and do not invent numbers.
- [ ] **Step 3:** Scan the checked-out SecRAGraph repository once as an **unlabeled** workload (or invoke the Compose adapter on its recognized files) and record revision, eligible/scanned files, status, time and unreviewed findings separately from TP/FP/FN. Do not call this an accuracy result.
- [ ] **Step 4:** Update README/architecture/demo and the new evidence document with measured counts and declared-only, no-effective-merge limits; describe API/CLI/LangGraph sharing and the Checkov input correction. Include source links from the design, and explicitly say author-created labels are regression evidence.
- [ ] **Step 5:** Run documentation tests, benchmark loader tests, Compose evidence-gate tests, JSON parsing, `git diff --check` and a brief human review for stale 14-case/current-engine claims. Commit only this task's files after review.

### Task 5: Integrator verification, independent review and merge

**Files:** No product files unless the review finds an evidenced defect.

- [ ] **Step 1:** Verify `uv lock --check`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src apps scripts/local_up.py scripts/prepare_case_corpus.py scripts/run_dast_evidence.py scripts/run_history_evidence.py scripts/ci_container_image.py infra/scanners/install_trivy.py`, and `uv run pytest -q`; investigate any failure before changing code.
- [ ] **Step 2:** Request fresh independent review of security boundaries, Checkov path isolation, finding precision and coverage claims; resolve findings and rerun only affected local checks.
- [ ] **Step 3:** Push the feature branch and create a PR against the current `main`. Require GitHub CI's quality, tests, container-build, compose-smoke, DAST, dependency-security, Git-history-secret and CodeQL checks to pass; read actual benchmark evidence before finalizing documentation.
- [ ] **Step 4:** After complete green checks and clean mergeability, merge the PR as the previously authorized next phase. Verify remote `main` commit, successful main CI and published evidence. Keep the PR linked to this task.
