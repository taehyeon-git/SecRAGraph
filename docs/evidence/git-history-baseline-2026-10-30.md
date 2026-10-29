# Git history secret scan baseline

The first full reachable-history scan was run against `main` commit
`313a2adc3968a37a1ce63d41a3d7531468a93d00` with pinned Gitleaks
`8.30.1`. The engine selected **19 commits**, completed successfully, and
returned **20 pattern-based candidates** across 16 distinct path/line pairs.
This is a baseline observation, not a claim that every possible secret was
found or that a pattern match proves an active credential.

The 20 candidates were reviewed without publishing values or filenames:
8 occurred in test/example material, 2 in documentation/sample material,
8 had explicit synthetic markers in source/config context, 1 had a nearby
JSON test marker, and 1 was a 64-character hexadecimal JSON value. The last
value matched a SHA-256 digest recomputed from the committed blob referenced
by that JSON at the same commit. No candidate in this baseline was confirmed
as a live credential. This review does not replace owner validation if a
credential's status later changes.

To reproduce locally, check out the named commit with complete history and
Gitleaks `8.30.1`, then run:

```powershell
uv run security-review scan-history . --head 313a2adc3968a37a1ce63d41a3d7531468a93d00 --format json --output build/private-history-baseline.json
```

The command exits nonzero because it finds candidates. Keep the local report
private: historical filenames can themselves be sensitive. CI does not use a
baseline allowlist. PRs and pushes inspect their newly selected commit range,
fail on any new candidate, and publish public evidence only after a completed,
zero-finding `main` push.
