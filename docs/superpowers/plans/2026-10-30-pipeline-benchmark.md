# Whole-tool pipeline benchmark implementation plan

Spec: `docs/design/pipeline-benchmark.md`

## Task 1: API end-to-end evidence

- Add focused failing tests for member login, mixed ZIP scan, persisted JSON/Markdown/SARIF, owner isolation, coverage and redaction evidence.
- Extend the isolated Compose smoke script to emit a bounded JSON/Markdown benchmark with stage timings and explicit limitations. Keep the same isolated stack and cleanup discipline.
- Run the Compose benchmark locally, inspect actual engine coverage and fix any scoreable gaps in the harness. Avoid absolute latency gates.

## Task 2: Whole-run bundle

- Add tests for missing, stale, malformed or incomplete component evidence and distinct denominator preservation.
- Add an aggregator that validates artifacts from the same workflow run and writes one JSON/Markdown benchmark. Add a dependent `main` aggregate CI job and preserve existing trusted-branch publication conditions. PRs exercise its fixture tests without publishing a cross-job bundle.
- Include the dependency audit, image/SBOM and history gate as separate operational tracks; do not call them member-upload accuracy.

## Task 3: Result-driven enrichment improvement

- Benchmark repeated identical finding queries on the unchanged scan graph and save baseline command/output.
- Add tests for duplicate, distinct, empty and failure responses, deadline behavior and graph reuse across invocations.
- Cache only validated retrieval results per invocation by exact query; run identical benchmark and unit tests after the change.
- Add failing OSV-only and mixed-finding RAG tests from the controlled contract's observed gap, then include OSV additions in enrichment without changing deterministic finding priority or global cap.

## Task 4: Integration, review and publication

- Run targeted and full unit tests, Ruff, mypy and relevant Compose/Docker checks. Check generated JSON/Markdown and the CI YAML.
- Independently review spec compliance, correctness and security; fix findings and rerun affected checks.
- Update README with the benchmark command, measured run identity, baseline/final comparison and honest limits. Commit, push, open PR, wait for required checks, squash merge and verify main artifact.
