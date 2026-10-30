# Multi-engine scanner evaluation

- Scope: synthetic_regression
- Corpus: SecRAGraph multi-engine authored regression fixtures
- Manifest SHA-256: `682c1c180ed5e8e20c6fc937bc919f8d3bef5da3af35328800496134f3624152`
- Cases scanned: 14/14
- Scored assessments: 42/42
- Unscored assessments: 0
- Unassessed findings: 0
- Traces verified: 4/4 scored expectations
- Wall time: 136905 ms

Incomplete or unavailable engines are unscored, not counted as false negatives.
Author-written fixtures measure regression behavior, not real-world detection.
Unassessed findings are excluded from the reported precision denominator.

## Engine coverage and time

| Engine | Completed / runs | Eligible files | Tool-confirmed files | Time (ms) |
| --- | ---: | ---: | ---: | ---: |
| `checkov` | 2/14 | 3 | 3 | 14304 |
| `gitleaks` | 14/14 | 30 | 1 | 7122 |
| `opengrep` | 11/14 | 25 | 25 | 115205 |
| `osv` | 0/14 | 0 | 0 | 0 |

## Labeled rule results

| Engine / rule | TP | FP | FN | Precision | Recall | F1 | Scored |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `checkov:CHECKOV/CKV2_AWS_5` | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `checkov:CHECKOV/CKV2_AWS_6` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV2_AWS_61` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV2_AWS_62` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV_AWS_144` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV_AWS_145` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV_AWS_18` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV_AWS_21` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1 |
| `checkov:CHECKOV/CKV_AWS_23` | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `checkov:CHECKOV/CKV_AWS_24` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `gitleaks:GITLEAKS/generic-api-key` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/javascript-web-command-taint` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/javascript_eval_rule-eval-with-expression` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/javascript_react_rule-dangerouslysetinnerhtml` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/python-web-command-taint` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/python-web-sql-taint` | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 | 4 |
| `opengrep:OG/python_deserialization_rule-pickle` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/python_deserialization_rule-yaml-load` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 2 |
| `opengrep:OG/python_eval_rule-eval` | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 3 |
| `opengrep:OG/python_exec_rule-subprocess-popen-shell-true` | 2 | 1 | 0 | 0.667 | 1.000 | 0.800 | 4 |
| `opengrep:OG/python_sql_rule-hardcoded-sql-expression` | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 | 4 |

## Source-to-sink trace verification

| Case / rule | Expected source | Required steps | Expected sink | Trace status |
| --- | --- | --- | --- | --- |
| `python-web-command-flow` / `OG/python-web-command-taint` | `python_command_positive.py:9` | `python_command_positive.py:4` | `python_command_positive.py:10` | verified |
| `python-web-sql-flow` / `OG/python-web-sql-taint` | `python_sql_positive.py:2` | `python_sql_positive.py:2` | `python_sql_positive.py:3` | verified |
| `javascript-web-command-flow` / `OG/javascript-web-command-taint` | `javascript_command_positive.js:8` | `javascript_command_positive.js:3` | `javascript_command_positive.js:9` | verified |
| `flask-header-sql-flow` / `OG/python-web-sql-taint` | `flask_header_sql_positive.py:5` | `flask_header_sql_positive.py:5` | `flask_header_sql_positive.py:6` | verified |

## Measurement notes

This is one offline run of the rebuilt pinned Linux scanner image
`sha256:b075d11529836111392d515304f22f4d8883405629e13c7fbfc449df38a0d128`
against the 14 authored case groups in
[`data/evaluation/multiengine_cases.json`](../../data/evaluation/multiengine_cases.json).
The 30 inert source files yielded 42 labeled engine/rule/file assessments:
27 positive line labels and 15 benign file labels. Every finding in this run
was covered by an assessment. The aggregate was TP=26, FP=1, FN=1, with
assessed precision, recall and F1 each 26/27 (0.963 when rounded).

The false positive is the bundled Opengrep shell-pattern rule on a command
constructed from `int(request.query_params.get("id"))`; the separate taint
rule correctly treats that conversion as a sanitizer. The false negative is
the bundled SQL rule on an f-string query built from explicit `input()` data.
The new taint rule covers separately labeled web-input SQL f-string cases.
These are distinct rule assessments, so the results preserve both limitations.

Four expected traces were checked against actual normalized source, required
intermediate step and sink locations. The Python and JavaScript command cases
traverse relay functions. The Flask SQL case traces `request.headers.get` to
the query, while its parameterized counterpart is clean. The bundled scanner
runs intrafile taint analysis; this result does not demonstrate tracing across
files or a whole program. The
[JSON record](multiengine-scanner-2026-10-27.json) includes each observed
trace's path, line and role, with no source values.

`Completed / runs` includes skipped runs in the denominator. Opengrep
completed all 11 runs with SAST-eligible files and skipped 3. Checkov completed
both runs with IaC files and skipped 12. Gitleaks completed all 14. OSV skipped
all 14 because these case groups contain no dependency manifests. For
Gitleaks, `Tool-confirmed files` counts files with a reported finding; 30 files
were submitted under completed runs. Rule-specific execution time cannot be
isolated from a shared rule-bundle scan, so time is reported by engine and for
the full run. Timings are from one run and vary by host.

The repository source was treated as data and never imported or executed.
The container had no network access and a read-only root filesystem; scanner
scratch space and inert source snapshots used separate temporary mounts.
These authored examples are regression evidence, not an estimate of accuracy
on independent repositories.

## 2026-10-31 rule quality follow-up

The two errors above were reproduced as red tests against the official
Opengrep 1.32.0 Windows release (asset SHA-256
`ae7152809ec71340213e8f4de3701c83edbdb33f4ac05eca2987b96ec6826a5e`).
The original broad shell YAML is unchanged. The Opengrep adapter now excludes
its finding only when the scanned Python AST shows that every f-string
interpolation comes from immediately preceding, simple `int(...)`
assignments in the same statement block and no `int` shadowing or dynamic
execution is visible in that file. Conditional conversion, tuple
reassignment, unknown variables, and cross-file calls retain the original
finding. If another `subprocess` call appears on the same source line, the
adapter retains every finding on that line because report filtering is keyed
by line number. The parser is capped at 100 KB and 10,000 AST nodes; parse or memory
failures retain the finding. This static proof cannot rule out arbitrary
runtime monkeypatching. The locally adapted SQL rule detects an interpolated
f-string query and leaves a parameterized query clean. The tests are in
[`test_opengrep_rule_quality.py`](../../tests/integration/scanner/test_opengrep_rule_quality.py).

The original 25 SAST-eligible authored files, before any cross-file corpus
extension, were scanned together with all 79 vendor rules and the project
taint rules. Opengrep confirmed 25/25 files with no errors or skipped paths.
For the original 27 exact rule/file/line assessments, the result moved from
TP=13, FP=1, FN=1 to TP=14, FP=0, FN=0. This is a regression-corpus result,
not an independent accuracy estimate.

The [vendor manifest](../../data/engines/opengrep/manifest.json) records the
SQL rule's local SHA-256 and original upstream SHA-256 under `local_patches`.
The shell rule and 77 other YAML files remain byte-identical to the pinned
upstream MIT revision. The [OWASP challenge manifest](../../data/evaluation/owasp_python_v0.1_challenge.json)
(SHA-256 `1228a6de3d8a318bea1d3ba565161b98040ccb78895b8526f7ea4783fd09b594`)
pins the local SQL rule and original shell rule, along with the official
BenchmarkPython revision, CSV, and all 90 selected source hashes.

On those 90 hash-verified external cases, the shell rule before and after
adapter filtering scored TP=7, FP=7, FN=6, TN=0 on CWE-78. No case met the
strict numeric-only exclusion. The SQL rule before and after its patch scored
TP=0, FP=0, FN=5, TN=11 on CWE-89. The full Python
vendor-plus-project-taint bundle also remained TP=27, FP=19, FN=9, TN=35 as a
broad-CWE union. These are case-level labels, not line-level rule truth. The
unchanged external result shows no loss of the original broad shell findings
on this pinned challenge; it does not imply those findings are all valid
injection reports.
