# Expanded Scanner Corpus Design

## Intent

Broaden the portfolio's keyless scanner evaluation beyond the original 53 author-created cases. Exercise every existing rule across more supported file formats, invocation forms, benign boundaries, nested paths, and multiple findings in one file. Measure the expanded corpus through both the local scan path and the real member-authenticated API without treating synthetic accuracy as an estimate for arbitrary repositories.

## Approach

1. Preserve the original 53-case manifest byte-for-byte under `data/evaluation/history/` so its published SHA-256 and authenticated evidence remain reproducible. Keep the earlier 39-case baseline and all dated evidence unchanged.
2. Extend `data/evaluation/scanner_cases.json` with at least 100 total cases, including all eight current rule IDs; Python, JavaScript, TypeScript, `.env`, JSON, YAML, YML, TOML, and INI; a useful positive/benign mix; and several files with more than one expected finding. Declare semantic labels in the manifest before measuring scanner output. Do not relabel unsupported dangerous sinks as benign or suppress their findings through `unassessed_rules` merely to obtain a perfect score.
3. Retain the exact `(case ID, rule ID, line)` scoring and strict nonzero exit on finding mismatch or incomplete coverage. Correct per-rule benign denominators to include only eligible benign files whose extension that rule can scan. Overall benign denominator remains all eligible benign cases.
4. Replace the unit contract that assumes every positive has one same-format negative with checks that the 53 historical cases are unchanged and that the expanded corpus covers the chosen dimensions. Update frozen aggregate/hash assertions only after inspecting the actual result.
5. Commit the corpus, tests, and any necessary scanner/scoring fixes before running the live authenticated evaluator. Capture local and API results at that clean code revision, compare every case, archive sanitized evidence, and update README, demo, architecture, operations, and corpus documentation. Explain the date, denominator, supported scope, and limitations separately from historical 39/53 and the existing OWASP BenchmarkPython challenge.

## Boundaries

- No scanner source file is executed or imported during evaluation.
- Candidate values are synthetic, nonfunctional secret-like strings, not working credentials. Published evidence contains case labels and paths, not raw source or session tokens.
- Current CWE/OSV and model lookups are disabled in the authenticated benchmark; container image preparation may still require network access.
- Known unsupported sink families remain explicit limitations and are not scored as safe negatives. The separate OWASP challenge still supplies a more independent but narrow real-project-style comparison.
- Case count is a documented snapshot, not a runtime limit; new cases can be added later without changing the evaluator interface.
