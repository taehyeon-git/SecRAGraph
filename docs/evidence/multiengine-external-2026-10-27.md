# Multi-engine scanner: external and real-repository measurements

Measured on 2026-10-27 in the local Linux Docker runtime image with 2 CPU and
2 GiB memory limits. The container had `--network none`; target source was
read as data and was never imported or executed. Wall times are observations
from this machine, not stable performance guarantees.

## Official OWASP BenchmarkPython v0.1 challenge

Source: [OWASP-Benchmark/BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba),
revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, GPL-3.0-only.
Ground truth: [official expectedresults-0.1.csv](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/expectedresults-0.1.csv),
SHA-256 `0c5ae0f9a8cdcb49549c459a25651cc058c7b17d621fc064ade2bd942dad80b8`.
The [pinned local manifest](../../data/evaluation/owasp_python_v0.1_challenge.json)
(SHA-256 `c12fdfac66d77161b4391cea6b134281891ce3d83d41ec2abdd82b89d64de0a2`)
records hashes of all 90 selected source files and all 18 assessed rule entries
(16 vendored MIT rules and two project-authored Python taint rules).
The GPL corpus is **not copied into this repository**.

The official CSV labels a **whole test case** vulnerable or benign for one CWE.
It supplies neither a vulnerable source line nor per-rule expected behavior.
This challenge selects the 90 cases labeled CWE-78, CWE-89, or CWE-502 and
maps the included vendor and project rules to those categories using their `metadata.cwe`.
The per-rule FN count therefore means “a positive case in the same broad CWE
where this one rule did not fire.” A rule may be designed for only one sink
within that CWE. These figures cannot be compared directly with the project's
line-labeled authored regression cases or interpreted as real-world precision.

Opengrep 1.32.0 reported `completed`, with 90/90 files confirmed scanned and
zero unscored cases. Full-bundle scan time was **10,706 ms**.

| Scope | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Selected CWE union, 90 cases | 27 | 19 | 9 | 35 | 0.587 | 0.750 |
| CWE-502, 54 cases | 18 | 12 | 0 | 24 | 0.600 | 1.000 |
| CWE-78, 20 cases | 7 | 7 | 6 | 0 | 0.500 | 0.538 |
| CWE-89, 16 cases | 2 | 0 | 3 | 11 | 1.000 | 0.400 |

Every assessed rule also ran separately against the cases in its CWE. All 18
single-rule runs completed. Their individual times include tool startup and
version probing; they are **not additive** to the bundle time. The complete
per-rule broad-CWE results were:

| Rule ID (`OG/python_` prefix for vendored rows) | TP | FP | FN | TN | Cases | Isolated time (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deserialization_rule-cpickle` | 0 | 0 | 18 | 36 | 54 | 3,068 |
| `deserialization_rule-dill` | 0 | 0 | 18 | 36 | 54 | 3,182 |
| `deserialization_rule-marshal` | 0 | 0 | 18 | 36 | 54 | 3,166 |
| `deserialization_rule-pickle` | 13 | 7 | 5 | 29 | 54 | 3,209 |
| `deserialization_rule-shelve` | 0 | 0 | 18 | 36 | 54 | 2,618 |
| `deserialization_rule-yaml-load` | 5 | 5 | 13 | 31 | 54 | 2,968 |
| `django_rule-django-extra-used` | 0 | 0 | 5 | 11 | 16 | 2,544 |
| `exec_rule-exec-used` | 0 | 0 | 13 | 7 | 20 | 2,807 |
| `exec_rule-os-path` | 0 | 0 | 13 | 7 | 20 | 2,972 |
| `exec_rule-os-popen2` | 0 | 0 | 13 | 7 | 20 | 3,165 |
| `exec_rule-paramiko-calls` | 0 | 0 | 13 | 7 | 20 | 2,841 |
| `exec_rule-start-process-with-no-shell` | 0 | 0 | 13 | 7 | 20 | 2,708 |
| `exec_rule-subprocess-call` | 0 | 0 | 13 | 7 | 20 | 2,782 |
| `exec_rule-subprocess-popen-shell-true` | 7 | 7 | 6 | 0 | 20 | 2,795 |
| `exec_rule-subprocess-shell-TRUE` | 0 | 0 | 13 | 7 | 20 | 2,623 |
| `sql_rule-hardcoded-sql-expression` | 0 | 0 | 5 | 11 | 16 | 2,732 |
| `OG/python-web-command-taint` | 3 | 0 | 10 | 7 | 20 | 2,468 |
| `OG/python-web-sql-taint` | 2 | 0 | 3 | 11 | 16 | 2,593 |

The command below also writes this table and machine-readable evidence into
`build/evidence/external/`.
The exact recorded JSON SHA-256 for this run was
`1c02f974ea2c648b88aac8a53a09b6ec74961b20362d1516e6ec347c74e55901`.

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git build/external/BenchmarkPython
git -C build/external/BenchmarkPython checkout --detach f1291485808b66e20ddb6b01b10dc71b3df8c8ba
docker build --target runtime -t secragraph:evaluation .
New-Item -ItemType Directory -Force build/evidence/external | Out-Null
$repo = (Get-Location).Path
$out = (Resolve-Path build/evidence/external).Path
docker run --rm --network none --read-only --memory 2g --cpus 2 `
  --tmpfs /tmp/secragraph:rw,exec,nosuid,nodev,mode=1777,size=256m `
  --tmpfs /tmp/secragraph-snapshots:rw,noexec,nosuid,nodev,mode=1777,size=64m `
  --env PYTHONPATH=/workspace/src:/workspace `
  --mount "type=bind,source=$repo,target=/workspace,readonly" `
  --mount "type=bind,source=$out,target=/evidence" `
  --entrypoint /app/.venv/bin/python secragraph:evaluation `
  /workspace/scripts/run_owasp_case_challenge.py `
  --checkout /workspace/build/external/BenchmarkPython `
  --output-dir /evidence --require-complete
```

The runner checks the local checkout HEAD, CSV hash, and each selected source/rule hash before
scanning. `--require-complete` fails if the bundle or a requested rule timing
run is incomplete; `--skip-rule-timing` omits only the optional timing runs.

## Pinned real-repository workload

[Starlette](https://github.com/encode/starlette/tree/8aa828ceaff764a2e57932fb42fdf105a47c4c83)
was cloned at revision `8aa828ceaff764a2e57932fb42fdf105a47c4c83`
and scanned once with the same networkless runtime image. The host verified the
revision with `git rev-parse HEAD`; the container did not have Git, so the
generated JSON currently records `source_revision: null`. This is an
**unlabeled operational workload**. Its 78 findings have not been independently
adjudicated and are not TP or FP counts.

| Engine | Status | Submitted files | Proven scanned files | Findings | Time |
| --- | --- | ---: | ---: | ---: | ---: |
| Opengrep 1.32.0 | partial (`scan_partial`) | 84 | 49 | 78 | 12,453 ms |
| Gitleaks 8.30.1 | completed | 94 | 0 confirmed paths | 0 | 615 ms |
| Checkov 3.3.30 | partial (`unconfirmed_files`) | 8 | 4 | 0 | 7,721 ms |

Total wall time was 28,690 ms. Gitleaks does not expose an inspected-file
inventory in its JSON; zero confirmed paths does **not** mean zero files were
submitted. Opengrep and Checkov reported incomplete file coverage, so this
run cannot establish absence of vulnerabilities. The observed JSON SHA-256 was
`2087dd27527f6b9c650fbca80a4052661794893c23a123afb9039e4d94304d89`.

To repeat it, clone and check out the linked revision under
`build/external/starlette`, then run
`scripts.run_multiengine_benchmark --real-repo build/external/starlette`
inside the tool-equipped Docker image using the two tmpfs mounts above. The
runner writes operational coverage and time without an accuracy score.
