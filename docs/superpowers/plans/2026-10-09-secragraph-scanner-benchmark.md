# SecRAGraph Scanner Benchmark and Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure the existing deterministic scanner on labeled synthetic code, reduce its known Python false positives/misses, add two narrow rules, and publish reproducible before/after evidence.

**Architecture:** A pure metric layer compares labeled `(case_id, rule_id, line_start)` tuples with results from the public `scan_path` path. The scanner retains its non-executing text/secret path but uses Python AST for supported call rules and a bounded JS/env lexical check for one TLS flag; parse coverage gaps become warnings. CI enforces the final fixture contract, not a claim of real-world accuracy.

**Tech Stack:** Python 3.11+ stdlib `ast`/`json`/`tempfile`/`tokenize`, existing LangGraph scan facade, Pydantic, pytest, Ruff, mypy, SARIF.

**Spec:** `docs/superpowers/specs/2026-10-09-secragraph-portfolio-evidence-design.md` §§1–2, 4–6.

## Global Constraints

- Scanner inputs are never imported or executed; AST parsing is allowed.
- Fixtures contain invented values only, no real credentials, external source code, or copied team-project assets.
- Every benchmark case calls `scan_path`; no benchmark-only detection implementation.
- Metrics identify their synthetic corpus, exact denominators, skips, warnings, baseline revision, and current revision.
- Generated JSON/Markdown goes under ignored `build/evidence/`; default runner exits nonzero on unexpected finding, miss, or warning.
- No internet API deployment or authentication work.

## Review Focus

1. Invalid Python syntax must still receive `SEC001` scanning and a parse-coverage warning; a diagnostic fixture must exclude unassessed Python-call rules from a benign denominator (Tasks 1–2 tests).
2. A comment/string that spells `eval(` or `verify=False` must not become a Python code finding (Task 2 test).
3. An alias shadowed by a function parameter, assignment target, or nested scope must not be treated as its old imported library name (Task 2 test).
4. JS/TS block comments, line comments, regex literals, quoted/template examples, and `.env` value `1` must not trigger the TLS rule; template interpolation is documented as unassessed (Task 4 test).
5. A skipped/unsupported benchmark case or duplicate label must fail validation instead of improving a denominator (Task 1 test).

## File map

| File | Responsibility |
| --- | --- |
| `src/security_review/evaluation/scanner_models.py`, `scanner_benchmark.py` | Validated cases, exact-match metrics, `scan_path` runner, JSON/Markdown result. |
| `scripts/run_scanner_benchmark.py` | Thin benchmark command; default enforce and explicit baseline mode. |
| `data/evaluation/scanner_cases.json` | New safe labeled source-text cases for all six rules. |
| `src/security_review/scanner/python_calls.py` | Non-executing AST call and simple import-alias recognition. |
| `src/security_review/scanner/node_tls.py` | Explicit Node TLS-disable assignment recognition outside strings/comments. |
| `src/security_review/scanner/rules.py`, `engine.py` | Rule metadata, AST/lexical finding assembly, compatibility wrapper and diagnostics. |
| `src/security_review/application.py` | Propagate syntax/coverage warnings into canonical scan reports. |
| `src/security_review/reporting/builder.py` | Bump the rule-set version after semantics/new rules change. |
| `docs/evidence/scanner-baseline.md` | Preserve measured pre-change output, runnable harness revision, corpus digest and exact reproduction command. |
| `tests/unit/evaluation/test_scanner_benchmark.py`, `tests/unit/scanner/test_python_calls.py`, `test_node_tls.py`, `test_engine.py`, `tests/e2e/test_cli.py`, `tests/unit/reporting/test_builder.py` | Metric, rule, deadline seam and report regression tests. |
| `README.md`, `docs/demo.md`, `docs/architecture.md`, `.github/workflows/ci.yml` | Measured before/after table, reproduction and keyless CI gate. |

---

### Task 1: Labeled corpus, metric engine, and pre-change baseline

**Files:** Create `data/evaluation/scanner_cases.json`, `src/security_review/evaluation/scanner_models.py`, `scanner_benchmark.py`, `scripts/run_scanner_benchmark.py`, `tests/unit/evaluation/test_scanner_benchmark.py`.

**Interfaces:** `load_scanner_cases(path: Path) -> tuple[ScannerCase, ...]`; `score_findings(expected: frozenset[FindingKey], actual: frozenset[FindingKey], eligible_benign_case_ids: frozenset[str]) -> ScannerMetrics`; `run_scanner_benchmark(cases_path: Path) -> ScannerBenchmark`; script `main(argv: Sequence[str] | None = None) -> int` with default enforce and `--baseline` to emit mismatches without failing. `FindingKey = tuple[str, str, int]` is `(case_id, rule_id, line_start)`. `ScannerCase` has `is_benign` (must equal `not expected`), `expected_diagnostics`, and `unassessed_rules` (empty in the fixed metric corpus). `ScannerBenchmark` separately exposes scanned/skipped/parse-warning coverage and expected/unexpected diagnostics.

- [ ] **Step 1: Write failing tests.** Exact-match TP/FP/FN include wrong-line-as-FP-plus-FN; precision/recall/F1 use explicit denominators and N/A for zero denominator; benign-case false-alarm rate counts only fully assessed benign cases, not findings. Reject duplicate case IDs/labels, a benign flag inconsistent with labels, path traversal, unsupported extension, blank text, oversize text, unexpected scan warnings/skips, and mismatch in enforce mode. Use a **fabricated scorer input** to prove that expected parse diagnostics leave a `SEC001` label scoreable, mark Python-call rules unassessed, and exclude that case from the benign denominator; Task 1 does not expect the pre-change scanner to emit this warning.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/evaluation/test_scanner_benchmark.py -q`; expect missing evaluator/module.
- [ ] **Step 3: Implement.** Store source as JSON strings and materialize each case inside an isolated temporary directory; pass it to `scan_path(..., ScanLimits())`, compare findings with labels, and never execute files. Include at least three positive and three paired negative cases for each existing/new rule (>=36 total), including multiline Python, comments, strings, placeholders, and safe alternatives; the fixed metric corpus uses valid syntax, while diagnostic-only malformed inputs are test fixtures. Validate label shape, but do not require its rule ID to exist in the pre-change registry so a baseline can score new-rule FNs. Derive eligible benign cases from empty labels **and** complete per-rule coverage; preserve expected diagnostics separately from unexpected warnings. Project away `ScanReport.scan_id` and `created_at` so two runs are byte-identical. Output corpus SHA-256 and revision metadata. CLI `--baseline` bypasses finding mismatches only, never hiding coverage errors.
- [ ] **Step 4: Run green tests.** `uv run pytest tests/unit/evaluation/test_scanner_benchmark.py -q`; expect exit 0.
- [ ] **Step 5: Commit the runnable harness.** Stage only Task 1 code/corpus/tests and commit `test: add labeled scanner benchmark runner`.
- [ ] **Step 6: Verify the baseline source.** Run `git diff ac88e9f -- src/security_review/scanner src/security_review/application.py src/security_review/orchestrator/scan_graph.py`; expect no output. Record the runnable Task 1 commit SHA.
- [ ] **Step 7: Measure the baseline.** Before Task 2 changes scanner code, run `uv run python -m scripts.run_scanner_benchmark --baseline`; expect JSON/Markdown with mismatches and no coverage failures.
- [ ] **Step 8: Preserve and commit baseline evidence.** Add `docs/evidence/scanner-baseline.md` with measured output, runnable commit SHA, scanner revision `ac88e9f`, corpus SHA and exact `git checkout <runnable-sha>` plus `uv run python -m scripts.run_scanner_benchmark --baseline` procedure. Commit only that document with `docs: record pre-change scanner baseline`.

### Task 2: Syntax-aware Python call rules and parse diagnostics

**Files:** Create `src/security_review/scanner/python_calls.py`, `tests/unit/scanner/test_python_calls.py`; modify `src/security_review/scanner/rules.py:13-30,55-89`, `engine.py:101-143`, `application.py:33-86`, `tests/unit/scanner/test_engine.py`, `tests/e2e/test_cli.py:92-99`.

**Interfaces:** `detect_python_calls(text: str, *, should_stop: Callable[[], bool] | None = None) -> tuple[PythonCallMatch, ...]` with `PythonCallMatch(rule_id: str, line_start: int)`; `scan_text_detailed(file_path: str, text: str, rules: Sequence[Rule] = DEFAULT_RULES, *, should_stop: Callable[[], bool] | None = None) -> ScanTextResult`, where `ScanTextResult` has `findings` and stable `warnings`. Existing `scan_text(...) -> tuple[Finding, ...]` remains a wrapper.

- [ ] **Step 1: Write failing tests.** Detect real direct/aliased `eval`, `subprocess.run/call/Popen(shell=True)`, `os.system`, `requests.<method>(verify=False)` across lines at the call-start line. Reject comments, quoted examples, `shell=False`, `verify=True`, imports shadowed by function parameters, reassigned names, and nested-scope bindings. Move the **real `scan_path` malformed-Python integration** assertion here: on syntax error keep a secret finding and return `python_syntax_error` warning through the canonical report; preserve custom regex rule injection and early `should_stop` behavior. Update the existing CLI deadline regression monkeypatch to the new detailed-scan seam without weakening its timeout assertion.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/scanner/test_python_calls.py tests/unit/scanner/test_engine.py -q`; expect missing AST detector and failed old-regex cases.
- [ ] **Step 3: Implement.** Change `Rule.pattern` to `Pattern[str] | None`, using `None` for AST-backed rules and preserving compiled patterns for custom/secret rules. Parse bounded `.py` text with `ast.parse` only; resolve direct calls and explicit `import ... as`/`from ... import ... as` bindings, invalidating aliases on assignment and local parameter/nested-scope shadowing. Check `should_stop` immediately before parsing, during AST traversal, and immediately after the synchronous parse; if the time budget is exhausted, return the existing processing-time warning rather than a complete-scan claim. Create findings through the existing `finding_id` and redaction path. Catch `SyntaxError`/`RecursionError` into a fixed warning without echoing source. Run `SEC001` even when AST parsing fails; report diagnostics via `_deterministic_scan`. Keep all other extension and custom-regex semantics.
- [ ] **Step 4: Run green tests.** `uv run pytest tests/unit/scanner/test_python_calls.py tests/unit/scanner/test_engine.py tests/unit/scanner/test_files.py tests/e2e/test_cli.py -q`; expect exit 0.
- [ ] **Step 5: Commit.** Stage Task 2 files and commit `fix: parse Python security calls without executing code`.

### Task 3: Narrow unsafe PyYAML loading rule

**Files:** Modify `src/security_review/scanner/python_calls.py`, `rules.py`; test `tests/unit/scanner/test_python_calls.py`, `tests/unit/reporting/test_sarif.py`.

**Interfaces:** Add `PY004` in `DEFAULT_RULES`: `category="code_pattern"`, CWE-502, severity high, confidence medium, remediation to use `yaml.safe_load` for untrusted YAML. `detect_python_calls` emits `PY004` at call-start line for supported unsafe loader forms.

- [ ] **Step 1: Write failing tests.** `yaml.unsafe_load(data)` and `yaml.load(data, Loader=yaml.UnsafeLoader)` trigger; imported aliases work; `yaml.safe_load`, `SafeLoader`, strings/comments do not. Verify SARIF rule ID, CWE reference and same finding ID as JSON.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/scanner/test_python_calls.py tests/unit/reporting/test_sarif.py -q`; expect no `PY004`.
- [ ] **Step 3: Implement.** Add metadata and AST check limited to explicit risky loader names. Do not infer whether `data` is attacker-controlled or claim exploitability.
- [ ] **Step 4: Run green tests.** Run the same pytest command; expect exit 0.
- [ ] **Step 5: Commit.** Stage Task 3 files and commit `feat: detect explicit unsafe PyYAML loading`.

### Task 4: Narrow Node TLS-disable rule

**Files:** Create `src/security_review/scanner/node_tls.py`, `tests/unit/scanner/test_node_tls.py`; modify `src/security_review/scanner/rules.py`, `engine.py`, `tests/unit/scanner/test_engine.py`.

**Interfaces:** Add `JS001` in `DEFAULT_RULES`: `category="configuration"`, CWE-295, severity high, confidence high, extensions `.js`, `.ts`, `.env`. `detect_node_tls_assignments(text: str, extension: str) -> tuple[int, ...]` returns 1-based assignment lines for only literal `0`.

- [ ] **Step 1: Write failing tests.** Accept `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"` in JS/TS and `NODE_TLS_REJECT_UNAUTHORIZED=0` in `.env`; reject value `1`, `//`/`/* */` comments, regex literals, quoted/template documentation, similar variable names, and text after a string boundary. Preserve CRLF line numbers and avoid duplicate findings. Explicitly test that template interpolation is *not assessed* rather than treating it as a safe negative.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/scanner/test_node_tls.py tests/unit/scanner/test_engine.py -q`; expect no `JS001`.
- [ ] **Step 3: Implement.** Give `JS001` a `None` regex pattern and use a bounded lexical pass for JS/TS quotes, template strings, regex literals, line/block comments and an anchored `.env` assignment pattern; do not add a JS runtime/parser dependency. Treat entire template literals, including interpolation, as unassessed and document that false-negative class. Assemble findings with the existing evidence-redaction and ID helper.
- [ ] **Step 4: Run green tests.** Run the same pytest command; expect exit 0.
- [ ] **Step 5: Commit.** Stage Task 4 files and commit `feat: detect explicit Node TLS verification disable`.

### Task 5: Final benchmark, documentation, and CI

**Files:** Modify `src/security_review/evaluation/scanner_benchmark.py`, `scripts/run_scanner_benchmark.py`, `tests/unit/evaluation/test_scanner_benchmark.py`, `src/security_review/reporting/builder.py`, `tests/unit/reporting/test_builder.py`, `README.md`, `docs/demo.md`, `docs/architecture.md`, `.github/workflows/ci.yml`.

**Interfaces:** Default `uv run python -m scripts.run_scanner_benchmark` emits `build/evidence/scanner.json` and `.md`, enforces exact labels and coverage, and returns 0 only for a passing corpus. Include baseline revision and before/after metric table in documentation.

- [ ] **Step 1: Write failing tests.** Two runner executions produce byte-identical sorted JSON and Markdown despite random `ScanReport.scan_id`/`created_at`, report all six rules and exact denominators/warnings, exit nonzero for altered labels/skips, and do not count syntax-error diagnostic cases as true negatives. Assert the new `RULE_SET_VERSION` in the canonical report and benchmark JSON/Markdown; assert new rule IDs/CWE mappings in SARIF, which does not currently expose the version. Exercise the real command in a temporary output directory and assert both artifacts exist and JSON parses; do not add tests that merely grep human prose or workflow YAML.
- [ ] **Step 2: Run red tests.** `uv run pytest tests/unit/evaluation/test_scanner_benchmark.py tests/unit/reporting/test_builder.py -q`; expect missing output/version behavior.
- [ ] **Step 3: Implement.** Bump `RULE_SET_VERSION` from `2026.10.1` to `2026.10.2`; re-run the *unchanged* manifest with final rules and capture actual before/after numbers plus corpus hash in README/demo docs. Project only stable benchmark fields, not report UUID/time. Include the default runner in the CI quality job alongside the RAG runner, followed by separate checks that `scanner.json` and `scanner.md` are nonempty and JSON parses. Keep generated files ignored under `build/evidence/` and avoid real-world accuracy claims.
- [ ] **Step 4: Run verification.** `uv run python -m scripts.run_scanner_benchmark`, then `uv run pytest tests/unit/evaluation tests/unit/scanner tests/unit/reporting tests/unit/docs -q`, `uv run ruff check .`, `uv run mypy src apps`; expect all exit 0. Inspect `build/evidence/scanner.json` and `.md` for correct counts and no actual secrets. Review README/demo/architecture prose and CI YAML against the spec manually.
- [ ] **Step 5: Commit.** Stage Task 5 files and commit `docs: report measured scanner benchmark and gate CI`.

## End-of-plan gate

Run `uv run pytest` with the repository's documented integration services, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src apps`, `uv run bandit -q -r src apps`, `uv run python scripts/ci_dependency_audit.py`, both evidence commands, and `uv run security-review scan src --format sarif --output build/self-scan.sarif` followed by `uv run python scripts/validate_sarif.py build/self-scan.sarif`. Record real results and skipped tests. Reconcile shared README/docs/CI changes from the RAG plan, review the final diff for secrets and path exposure, then publish only the safe branch after all required checks pass.
