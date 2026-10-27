# Scanner benchmark

Small, author-created synthetic corpus; these rates do not estimate performance on arbitrary repositories.

- Corpus SHA-256: `af99933a52a09d5e7a566a567382f2b13bce3d2047bafb1e597d7ea51d3dc403`
- Scanner baseline revision: `ac88e9f`
- Current revision: `fc6d3e4666004b4c68b738b2b63d799fe495d34c`
- Rule set version: `2026.10.4`
- Coverage: 120/120 scanned; 0 skipped; 2 parse warnings; 2 expected diagnostics; 0 unexpected diagnostics; 0 missing diagnostics

| Rule | TP | FP | FN | Precision (TP+FP) | Recall (TP+FN) | F1 | Benign alarms / eligible cases |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | 69 | 0 | 0 | 1.000 (69) | 1.000 (69) | 1.000 | 0/55 (0.000) |
| JS001 | 13 | 0 | 0 | 1.000 (13) | 1.000 (13) | 1.000 | 0/15 (0.000) |
| PY001 | 8 | 0 | 0 | 1.000 (8) | 1.000 (8) | 1.000 | 0/35 (0.000) |
| PY002 | 8 | 0 | 0 | 1.000 (8) | 1.000 (8) | 1.000 | 0/35 (0.000) |
| PY003 | 6 | 0 | 0 | 1.000 (6) | 1.000 (6) | 1.000 | 0/35 (0.000) |
| PY004 | 6 | 0 | 0 | 1.000 (6) | 1.000 (6) | 1.000 | 0/35 (0.000) |
| PY005 | 7 | 0 | 0 | 1.000 (7) | 1.000 (7) | 1.000 | 0/35 (0.000) |
| PY006 | 6 | 0 | 0 | 1.000 (6) | 1.000 (6) | 1.000 | 0/35 (0.000) |
| SEC001 | 15 | 0 | 0 | 1.000 (15) | 1.000 (15) | 1.000 | 0/55 (0.000) |

## Mismatches and diagnostics

- None
