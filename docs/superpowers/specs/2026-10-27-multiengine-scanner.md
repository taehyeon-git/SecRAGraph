# Multi-engine scanner design

## Goal

Replace the eight project-authored source/secret/configuration rules with specialized engines. Public repository CI uses CodeQL `security-extended`; private member uploads use LGPL Opengrep with a pinned MIT-licensed rule bundle for SAST, Gitleaks for secrets, Checkov for configuration, and the existing OSV lockfile audit for dependencies. The scan report must show which engines actually ran, what they inspected, and what they could not inspect.

## Boundaries and execution

- CodeQL is restricted to the public GitHub repository CI. It is never invoked on a member upload without a paid license. CodeQL workflow scans Python and, only when tracked JS/TS exists, JavaScript/TypeScript.
- Opengrep analyzes member source without building or executing it. This version's taint analysis is within a file; reports must not claim cross-file private-upload tracing. CodeQL source-to-sink paths in public CI demonstrate cross-file flow, with explicit framework sources and sanitizers where necessary. Semgrep Registry rules are not vendored because their license restricts redistribution.
- Each external tool receives a bounded, copied snapshot of only accepted UTF-8 files. The snapshot excludes symlinks, scanner config supplied by the target, executable hooks, large/binary files, and unapproved extensions. Subprocesses have timeouts and trusted configuration; errors remain `not_run`, `partial`, or `error`, never clean success.
- Gitleaks results are parsed in memory and immediately converted to fixed redacted evidence. Raw secrets, source snippets, and untrusted tool logs must not enter JSON, Markdown, SARIF, DB, or application logs.
- Checkov runs only non-executing IaC frameworks with remote downloads and custom checks disabled. OSV receives only normalized package coordinates from lockfiles.
- The API stays bound to localhost in Compose and member login remains required. No public deployment is part of this change.

## Report contract

`Finding` records the producing engine and optional text-free source/step/sink locations. `ScanReport.executions` records each engine's type, version, status, elapsed time, eligible and scanned relative paths, languages or frameworks, checks, and a short reason code. JSON, Markdown, and SARIF render the same coverage. Failed and partial runs produce a failed SARIF invocation rather than a misleading successful zero-result scan. PostgreSQL round-trips all fields through a migration.

## Evaluation contract

The original 120 author-written cases remain historical regression evidence only. New labeled fixtures include vulnerable and benign examples for SAST, secrets, configuration, and packages; evaluation reports per-engine and per-rule TP, FP, FN, coverage, and elapsed time. External corpora are identified by immutable commit and manifest hashes and read locally without executing upstream scripts. Unlabeled real repositories report coverage, finding counts, and timing only; they cannot yield TP/FP/FN until independently labeled. No 100% synthetic result is described as real-world detection rate.

## Acceptance

Fresh tests prove safe snapshotting, no raw-secret persistence, tool-unavailable reporting, external failure/timeout coverage, report/DB/SARIF round-trip, CodeQL CI setup, and honest evaluation denominators. Container runtime includes pinned scanner dependencies or reports unavailability explicitly. Existing API/CLI/member flows continue to work.
