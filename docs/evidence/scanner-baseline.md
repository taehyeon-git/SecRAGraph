# Pre-change scanner baseline

This is the measured result of the unchanged scanner at revision `ac88e9f` on a small, author-created synthetic corpus. It is evidence about these 39 cases, not an estimate of accuracy on arbitrary repositories. The runner invoked the public `scan_path` path for every case and did not execute any fixture source.

- Runnable harness commit: `915182f52b35d9f14714fd1c65f081b071f6b033`
- Scanner revision: `ac88e9f`
- Corpus SHA-256: `6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d`
- Coverage: 39/39 scanned, 0 skipped, 0 parse warnings, 0 expected diagnostics, 0 unexpected diagnostics, 0 missing diagnostics
- Exact-match findings: 9 TP, 6 FP, 9 FN
- Fully assessed benign cases with at least one false alarm: 6/21

The runnable harness commit has no changes relative to `ac88e9f` under `src/security_review/scanner`, `src/security_review/application.py`, or `src/security_review/orchestrator/scan_graph.py`.

## Reproduce

In a Git checkout with the project's development dependencies installed, run:

```sh
git checkout 915182f52b35d9f14714fd1c65f081b071f6b033
uv run python -m scripts.run_scanner_benchmark --baseline
```

The command writes stable `build/evidence/scanner.json` and `build/evidence/scanner.md`. `--baseline` permits labeled finding mismatches; skipped cases and unexpected or missing diagnostics still cause a nonzero exit. The recorded run exited 0. The command's generated Markdown was:

```text
# Scanner benchmark

Small, author-created synthetic corpus; these rates do not estimate performance on arbitrary repositories.

- Corpus SHA-256: `6d77a9b45f1d9df215892969d3af6ce95f61e4ed20202fad61a24a5330bd6c2d`
- Scanner baseline revision: `ac88e9f`
- Current revision: `915182f52b35d9f14714fd1c65f081b071f6b033`
- Coverage: 39/39 scanned; 0 skipped; 0 parse warnings; 0 expected diagnostics; 0 unexpected diagnostics; 0 missing diagnostics

| Rule | TP | FP | FN | Precision (TP+FP) | Recall (TP+FN) | F1 | Benign alarms / eligible cases |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | 9 | 6 | 9 | 0.600 (15) | 0.500 (18) | 0.545 | 6/21 (0.286) |
| JS001 | 0 | 0 | 3 | N/A (0) | 0.000 (3) | N/A | 0/21 (0.000) |
| PY001 | 3 | 2 | 0 | 0.600 (5) | 1.000 (3) | 0.750 | 2/21 (0.095) |
| PY002 | 2 | 2 | 1 | 0.500 (4) | 0.667 (3) | 0.571 | 2/21 (0.095) |
| PY003 | 1 | 2 | 2 | 0.333 (3) | 0.333 (3) | 0.333 | 2/21 (0.095) |
| PY004 | 0 | 0 | 3 | N/A (0) | 0.000 (3) | N/A | 0/21 (0.000) |
| SEC001 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/21 (0.000) |

## Mismatches and diagnostics

- `py001-direct-negative`: FP=[('py001-direct-negative', 'PY001', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py001-multiline-negative`: FP=[('py001-multiline-negative', 'PY001', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py002-run-negative`: FP=[('py002-run-negative', 'PY002', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py002-multiline-positive`: FP=[]; FN=[('py002-multiline-positive', 'PY002', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py002-multiline-negative`: FP=[('py002-multiline-negative', 'PY002', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py003-get-negative`: FP=[('py003-get-negative', 'PY003', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py003-multiline-positive`: FP=[]; FN=[('py003-multiline-positive', 'PY003', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py003-multiline-negative`: FP=[('py003-multiline-negative', 'PY003', 1)]; FN=[]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py003-alias-positive`: FP=[]; FN=[('py003-alias-positive', 'PY003', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py004-unsafe-positive`: FP=[]; FN=[('py004-unsafe-positive', 'PY004', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py004-loader-positive`: FP=[]; FN=[('py004-loader-positive', 'PY004', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `py004-alias-positive`: FP=[]; FN=[('py004-alias-positive', 'PY004', 2)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `js001-js-positive`: FP=[]; FN=[('js001-js-positive', 'JS001', 1)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `js001-ts-positive`: FP=[]; FN=[('js001-ts-positive', 'JS001', 1)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
- `js001-env-positive`: FP=[]; FN=[('js001-env-positive', 'JS001', 1)]; missing diagnostics=[]; unexpected diagnostics=[]; skipped=False
```

The pre-change `PY001`–`PY003` regular expressions account for the comment/string false alarms and multiline/alias misses. `PY004` and `JS001` are future-rule labels and have zero pre-change true positives by design.
