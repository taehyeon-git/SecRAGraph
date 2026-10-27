# Member-authenticated scanner evaluation

Every synthetic case was uploaded as a one-file ZIP through the API after member login. Each JSON report was retrieved from storage and compared with the upload response. The scanner findings use exact case, rule, and line labels.

- Authenticated uploads: 53/53
- Persisted reports verified: 53/53
- Finding locations verified: 25
- Missing session rejected (401): True
- Other member denied the report (404): True
- Revoked session rejected (401): True

# Scanner benchmark

Small, author-created synthetic corpus; these rates do not estimate performance on arbitrary repositories.

- Corpus SHA-256: `8cca80371d91e939c01274926547074cf26d23806f6e2432738446aa968bf826`
- Scanner baseline revision: `ac88e9f`
- Current revision: `af3844c9b7462c547c25e6dc37feb5e6728599fe`
- Rule set version: `2026.10.4`
- Coverage: 53/53 scanned; 0 skipped; 0 parse warnings; 0 expected diagnostics; 0 unexpected diagnostics; 0 missing diagnostics

| Rule | TP | FP | FN | Precision (TP+FP) | Recall (TP+FN) | F1 | Benign alarms / eligible cases |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | 25 | 0 | 0 | 1.000 (25) | 1.000 (25) | 1.000 | 0/28 (0.000) |
| JS001 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| PY001 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| PY002 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| PY003 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| PY004 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| PY005 | 4 | 0 | 0 | 1.000 (4) | 1.000 (4) | 1.000 | 0/28 (0.000) |
| PY006 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |
| SEC001 | 3 | 0 | 0 | 1.000 (3) | 1.000 (3) | 1.000 | 0/28 (0.000) |

## Mismatches and diagnostics

- None
