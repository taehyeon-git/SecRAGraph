# Git history secret scanning implementation plan

## Outcome

Add a trusted local/CI Gitleaks history path with redacted commit provenance and a fail-closed CI gate. Keep member upload behavior unchanged.

## Tasks

1. **Provenance model and storage (TDD).** Add `Finding.git_commit` (source path+line only, no trace) and history-only `ScanExecution` bounds/count with strict validation. Require head SHA and positive count together; allow optional base SHA; reject revision fields on non-secret executions. Preserve these through LangGraph rebuilding and protected-field checks. Add ORM mapping, database check, and Alembic 0008; test old-row compatibility, round trip, and downgrade refusal with historical rows.
2. **Truthful reports (TDD).** JSON exposes the validated commit; Markdown branches on history coverage before snapshot Gitleaks text and labels the selected range; SARIF emits logical historical locations and commit-sensitive fingerprints without current-file physical locations. Add deleted-file and same-line/different-commit tests.
3. **Bounded engine (TDD).** Validate local checkout, full SHAs, commit objects, ancestry, shallow state, selected commit count (max 10,000), and repo-root ignore. Invoke only pinned Gitleaks Git mode with trusted config and a minimal secret-free template, fixed Git options, 300-second deadline, 32 MiB metadata cap, 2,000-finding cap, and cleanup. Sanitize Git environment and disable replacement objects, lazy fetch, and user global/system config. Parse selected commit/path/line metadata; redact all messages. Test runtime-generated add/delete key, root and merge commit, false-positive, malicious path/ref, timeout, partial output, and no raw secret retention.
4. **CLI and LangGraph (TDD).** Add `scan-history` with default HEAD/full reachable history and optional SHA bounds. Use the shared precomputed-findings graph/report builder once. Generate JSON/Markdown/SARIF from the same `ScanReport`, and return nonzero on findings or incomplete coverage. No API/ZIP route.
5. **Independent CI evidence.** Factor a gitleaks-only SHA-verified installer without changing the existing Docker installer. Add full-depth, credential-free checkout job; PR head/base inputs with exactly one merge base and local head object; push before/after inputs with all-zero-only full-history fallback; one scan; separate artifact validation and fail-closed finding gate; and sanitized main-push artifacts even when findings fail the gate. Never upload incomplete output. Add workflow/script tests and run on GitHub Actions.
6. **Review and integration.** Run targeted and full unit suites, migration integration, Ruff/mypy/Bandit, a real pinned Gitleaks scan of temporary Git history and the current main's full history as an initial baseline, independent code/security review, then PR CI and merge to main. Record the full-history baseline result plus measured scope and limits in README and threat model.

## Interface and safety constraints

- Historical findings carry full commit SHA and no raw secret, match, or source line.
- Gitleaks template uses only `RuleID`, `File`, numeric locations, and `Commit`; the parser rejects unknown commits and unsafe paths.
- `--log-opts` consists solely of `--full-history -m --no-ext-diff --no-textconv --no-renames` and `git rev-parse`-canonicalized full SHAs. Trusted `--config` and empty `--gitleaks-ignore-path` live outside the repository. No arbitrary Git ref, URL, shell, checkout, hook, or submitted repository enters the command.
- Shallow/incomplete/over-cap scans fail closed; a zero-finding result is only success when the selected commit count and scanner completion are proven.
- History SARIF is an artifact with logical locations, not a current-file Code Scanning upload.
