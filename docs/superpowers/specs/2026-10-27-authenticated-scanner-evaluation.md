# Authenticated Scanner Evaluation Design

## Intent

Show what the fixed synthetic scanner evaluation produces when a real member logs in, uploads every case through FastAPI, and retrieves the persisted reports. Keep this separate from the historical local benchmark and from claims about arbitrary repositories.

## Approaches

- An in-process API test is cheap but does not prove the deployed login, upload, and persistence path.
- Manually using an existing account is difficult to reproduce and risks leaking credentials or changing the user's reports.
- Selected: launch an isolated loopback Docker Compose stack, create two temporary members by passing credentials through stdin, and evaluate all cases over HTTP. Delete the isolated containers and volumes after the run.

## Workflow and evidence

1. Read and validate the current `scanner_cases.json`; do not hardcode 53 as a runtime limit. Turn each case into a one-file ZIP so nested source paths and `.env` survive upload.
2. Start a production-mode API with no model key and automatic OSV/CWE lookup disabled. Generate ephemeral database and member credentials; never write them to evidence, argv, or logs.
3. Login with `/v1/auth/login`, upload each ZIP with `Authorization: Session <token>`, check the source path and report rule version, and GET the persisted JSON report for the same member.
4. Reuse `assess_scanner_case` and `score_findings` for exact `(case ID, rule ID, line)` TP/FP/FN. Count successful uploads, persisted reads, path matches, and diagnostic gaps. Verify unauthenticated 401, a second member's 404, and 401 after logout.
5. Write only safe JSON/Markdown evidence in ignored `build/evidence`; commit a dated summary with corpus hash, source revision, counts, denominator, and limitations. README shows the authenticated API result in its own row, alongside the historical local baseline.

## Boundaries

The assessment uses author-created synthetic files, so matching scores show route parity on this corpus, not real-world detection quality. Failing requests or incomplete coverage make the command fail; no partial passing score is reported. Actual passwords, session tokens, uploaded source, and report UUIDs never appear in published evidence. The scanner is deterministic and does not need a model key.
