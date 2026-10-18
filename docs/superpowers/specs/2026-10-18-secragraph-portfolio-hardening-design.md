# SecRAGraph portfolio hardening design

Date: 2026-10-18
Status: approved for implementation under the user's instruction to independently review the plan and proceed
Base: public `main` tree `1bfda0075578e7bb575a8fb6175009e270990ee3`

## Intent and boundary

Make the existing backend/DevSecOps portfolio safer to demonstrate and easier to verify. Preserve a keyless, offline default; never execute scanned code; do not deploy an internet-facing API. Publish only verified source, tests, and documentation to the existing GitHub `main`. The user's request to fix all previously listed gaps is interpreted as implementing the strongest useful local-portfolio controls, while stating what cannot be honestly proven without an API key, licensed external data, or a multi-user deployment.

## Approach decision

Considered (1) documentation-only polish, (2) local-first hardening with optional live/external evaluation, and (3) a production multi-tenant service. Choose (2): it directly demonstrates backend and DevSecOps engineering without introducing a public identity provider, cloud costs, or claims that the offline test proves model quality. Every new optional integration must fail clearly when unavailable and must not alter the keyless CI path.

## 1. Report privacy and local API access

Scanner findings will expose only rule-owned constant evidence labels. No arbitrary source-line substring, comment, literal, or unmatched credential text may enter `redacted_evidence` or source-derived fields of JSON, Markdown, SARIF, and persisted new reports. The file, line, rule, severity, CWE, and remediation remain. Caller-provided target names, file paths, warnings, and citation metadata can themselves be sensitive and are explicitly documented as report data. IDs/fingerprints must be deterministic for the same rule/path/line and independent of unrelated source-line text. A database migration replaces legacy persisted evidence text with a constant marker; previously exported reports cannot be recalled and that caveat is documented. Tests use synthetic source-line canaries across scanner and report boundaries.

For the single-user local demo, a configured API token protects direct calls to all `/v1` routes using constant-time comparison of an `Authorization: Bearer` header before request-body buffering. `/health` stays available for Compose readiness. Production-mode API startup requires a nonblank token even if a testing flag is set; tests and explicit local development can run without one. Compose requires a user-provided token and passes it to the Streamlit client; no example credential is committed. Streamlit becomes a token-bearing proxy on the same host, so this does not authenticate UI users or protect against all same-host clients; Qdrant also remains local-only. Public or multi-user deployment remains unsupported and documented as such.

## 2. Evaluation honesty and reproducibility

Keep the four-case keyless LangGraph/Qdrant evaluator and the synthetic scanner regression benchmark as default CI gates. Add a separately named, opt-in live-provider RAG evaluation command that requires a provider key and records model IDs, corpus/case digests, per-case route/retrieval/citation/abstention checks, latency, errors, and a human-review field for factual support. It must not silently turn a model answer into a claim of factual correctness; no live result is advertised until run with a real key. Fake-provider tests prove gating, bounded execution, result schema, and failure isolation without network.

Add an opt-in evaluator for a user-supplied, pinned local checkout of OWASP Benchmark for Python. Do not vendor its GPL-licensed source or execute it. Treat the declared CWE-78/PY002 and CWE-502/PY004 mappings as a broad-CWE challenge, not exact sink coverage: upstream cases also use `sh -c` without `shell=True` and `pickle.loads`, which these rules do not detect. Score at case level rather than source-line level, report excluded categories, unsupported sink examples, missing files, and denominators, and fail on unpinned or malformed input. Missing challenge-case source produces a bounded error record listing the IDs and original labeled denominator plus a nonzero exit; it is never silently dropped. Low recall is an honest result, not an evaluator failure. The existing synthetic 39-case result remains clearly labeled as a regression fixture, not field precision/recall.

## 3. Knowledge provenance and freshness

Support a local, versioned manifest for ingested Markdown with publisher URL, license, source revision/date, SHA-256, and corpus ID. Read each source once into a bounded immutable snapshot, validate its digest, then decode/chunk/embed that same snapshot before writing to Qdrant; do not reopen after validation. Propagate safe source URLs into citations and write a bounded receipt under ignored local `build/evidence/`, never in public CI artifacts. Existing manifest-free demo ingestion remains available but is labeled unverified. The verified loader may return an empty desired corpus for preview/sync, whereas ordinary ingestion may reject it. Managed document/point IDs must be namespaced by corpus ID so a same-path untagged or other-corpus document cannot be overwritten by upsert. An explicit corpus reconciliation first replaces all chunks of desired documents (including a same-identity document whose text shrank), then previews/removes absent managed documents when requested, using corpus and generation guards; it never touches untagged or another corpus's points. An empty desired corpus is previewable, but applying deletion of its final document requires an additional explicit `--allow-empty` flag. After a successful sync, changed text, changed identity fields, and removed Markdown files must no longer be searchable in the selected managed corpus. Qdrant has no cross-batch transaction here: a failed upsert may leave a partially refreshed selected corpus. Such failures must be reported, must not trigger stale-point deletion, and must be recoverable by rerunning sync; no atomic-swap claim is made. No automatic internet fetch or PDF parser is introduced: those would add new untrusted-input and licensing surfaces without helping the present local proof.

Synthetic CSV intelligence remains demo-only. Documentation must distinguish import time from upstream publication/freshness and show how a licensed source snapshot can be recorded; no claim of a live CVE feed is made.

## 4. Inspectable DevSecOps proof

CI continues Ruff, mypy, Bandit, dependency audit, full tests, and image build. Upload only bundled-synthetic keyless RAG/scanner JSON and Markdown as workflow artifacts with retention on a trusted `main` push; pull-request runs still verify the files but do not publish them. Add an always-on Compose contract test for loopback bindings and a dedicated bounded Compose smoke gate for API, web, migration, and an authenticated synthetic scan, with isolated project name, generated secrets, no persistent shared volumes, and cleanup. The local demo UI must distinguish no-key offline evidence from provider-backed Q&A, and make scan findings and report formats easier to inspect.

README/demo/operations/security docs must link current evidence rather than imply the older `v0.1.0` release contains these changes. A new release is not required for this change; the current `main` commit and its checks are the authoritative proof. Do not publish generated evidence that can contain user code. CI artifacts contain only bundled synthetic inputs.

## Acceptance and residual limits

1. A synthetic unknown-secret canary present only in a scanned source line never appears in newly generated or migrated stored evidence, source-derived report fields, or API responses; stable IDs and ordinary findings remain usable. User-supplied paths and metadata are not claimed to be redacted.
2. Production-mode API refuses to start without a token. Configured wrong/missing tokens receive a consistent denial; health and correct-token workflows still operate. Compose remains loopback-only.
3. Keyless tests and evaluations pass. Live-provider and external-corpus evaluators are opt-in, bounded, and accurately label unexecuted/unsupported cases.
4. Manifest validation rejects changed bytes before provider writes, citations retain declared source URL, and explicit sync removes only stale points in the selected managed corpus.
5. CI produces downloadable sanitized evidence and verifies the full local image stack; documentation states exact commands, measured results, and limits.
6. No claim of measured live LLM answer quality, real-world scanner accuracy, PDF support, or multi-user authorization is made without the corresponding run/implementation. Internet API deployment is not performed.
