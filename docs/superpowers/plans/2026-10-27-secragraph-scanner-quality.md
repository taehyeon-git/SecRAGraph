# SecRAGraph Scanner Quality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add high-signal Python SQL-construction and pickle-deserialization findings, then measure them honestly in regression and external challenges.

**Architecture:** Extend the existing non-executing AST visitor and immutable rule registry. Keep exact-line deterministic findings and source-free evidence. Run existing synthetic benchmark as a regression gate and an independently pinned OWASP corpus as an optional external generalization check.

**Tech Stack:** Python `ast`, pytest, existing SecRAGraph scanner/evaluation modules.

**Spec:** `docs/superpowers/specs/2026-10-27-membership-scanner-rag-design.md`

## Global Constraints

- Never import or execute scanned source; preserve per-file time/size bounds and syntax warnings.
- No finding text or evidence includes source literals or credential values; report formats and CLI/API share the same findings.
- `PY005` is a syntactic CWE-89 heuristic for dynamic SQL at execution sinks, not taint proof. `PY006` is a CWE-502 warning for pickle APIs, not all deserialization.
- Paired benign/vulnerable tests must precede implementation; synthetic scores remain explicitly labeled as author-made regression evidence.
- External OWASP corpus remains opt-in, pinned, locally supplied, and unvendored; full denominators and unsupported sinks must be shown.

## Review Focus

1. SQL query built dynamically but passed with safe bound parameters must not be flagged merely for having `execute` (Task 1 test).
2. A function or module shadowing a targeted imported symbol must not trigger PY006 (Task 1 test).
3. A syntactically invalid Python source must continue to produce a coverage warning, not partial AST claims (Task 1 test).
4. New rules must emit exactly fixed, redacted evidence across JSON/Markdown/SARIF (Task 1 test).
5. External CWE mapping must not count unrelated supported rules as matches or silently drop missing challenge files (Task 2 test).

---

### Task 1: Narrow AST rules and paired regression cases

**Files:**
- Modify: `src/security_review/scanner/python_calls.py`, `src/security_review/scanner/rules.py`, `src/security_review/scanner/engine.py`, `src/security_review/scanner/redaction.py`
- Modify: `tests/unit/scanner/test_python_calls.py`, `tests/unit/scanner/test_engine.py`, `tests/unit/scanner/test_redaction.py`, `tests/unit/reporting/test_formats.py`
- Modify: `data/evaluation/scanner_cases.json`, `tests/unit/evaluation/test_scanner_benchmark.py`
- Modify rule-set constant wherever `rg RULE_SET_VERSION src tests` locates it.

**Interfaces:**
- `detect_python_calls(text, should_stop=...)` emits `PythonCallMatch('PY005', line)` for dynamic SQL expressions passed to an `execute`/`executemany` call or `sqlalchemy.text`, provided a literal SQL verb prefix is statically visible. f-string, `%`, `.format`, and string concatenation are supported; parameterized static statements are not matches.
- The same visitor emits `PythonCallMatch('PY006', line)` for `pickle.load`/`loads`, including aliases from `import pickle as p` and `from pickle import loads as x`, but not locally rebound names.
- `DEFAULT_RULES` and `safe_evidence` expose stable metadata/fixed evidence for both rules; report format schemas do not change.

- [ ] **Step 1: Write failing tests** for every positive syntax, paired parameterized/constant/non-SQL negatives, comments/strings, alias/shadowing, time-budget interruption, syntax error, and source canary absent from all report formats. Add at least three positive and three negative synthetic cases per new rule with exact start lines.
- [ ] **Step 2: Run red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/scanner tests/unit/evaluation/test_scanner_benchmark.py tests/unit/reporting/test_formats.py`.
- [ ] **Step 3: Implement** the two AST matches with bounded recursion and existing scope resolver, update rule registry/engine/redaction/version, and keep all source-derived strings out of findings.
- [ ] **Step 4: Run green** with the same tests and `python -m scripts.run_scanner_benchmark`; inspect TP/FP/FN denominators.
- [ ] **Step 5: Commit** the rules, fixtures, and tests.

### Task 2: External challenge mapping and reproducible evidence

**Files:**
- Modify: `src/security_review/evaluation/external_benchmark.py`, `src/security_review/evaluation/scanner_models.py`, `scripts/run_external_scanner_benchmark.py`
- Modify: `tests/unit/evaluation/test_external_benchmark.py`, `docs/demo.md`, `docs/architecture.md`, `README.md`

**Interfaces:**
- Broad case-level mapping includes CWE-89→PY005, CWE-78→PY002, CWE-502→{PY004,PY006}. `ExternalCase` records the expected rule family, matched rule IDs, and unsupported sink caveat without counting unrelated matches.
- Existing revision and CSV SHA-256 checks, missing/ambiguous case handling, and nonzero exit for malformed/incomplete corpora remain.

- [ ] **Step 1: Write failing tests** for CWE-89 and pickle challenge mapping, multiple allowed CWE-502 rules, unrelated-rule rejection, unchanged missing-case denominator, and output disclosure of low recall and unsupported sinks.
- [ ] **Step 2: Run red:** `.\.venv\Scripts\python.exe -m pytest -q tests/unit/evaluation/test_external_benchmark.py`.
- [ ] **Step 3: Implement** mapping/schema/report changes, with migration-free backwards-compatible JSON evidence where possible.
- [ ] **Step 4: Run green** plus `python -m scripts.run_scanner_benchmark` and SARIF validation; if a pinned OWASP checkout can be acquired legally and safely, execute it separately and record revision/hash/result without vendoring it.
- [ ] **Step 5: Commit** evaluation and documentation.
