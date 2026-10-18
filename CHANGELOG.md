# Changelog

## Unreleased (`0.2.0` package version; no release tag yet)

- Replaced scanner source-line evidence with rule-owned constants and added an irreversible migration for historical persisted evidence.
- Added a single-user bearer token gate to local production API routes, including the Streamlit-to-API path.
- Added opt-in live-provider RAG observations and a pinned local OWASP Python broad-CWE challenge adapter; keyless synthetic gates remain separate.
- Added digest-verified knowledge manifests and explicit, corpus-scoped Qdrant reconciliation with preview and guarded empty apply.
- Added trusted-main synthetic evidence artifacts, an isolated full-stack Compose smoke gate, and demo report downloads.

This is not a tagged release; `v0.1.0` predates these changes.

## 0.1.0

- Added deterministic static scanning for files, directories, and ZIP archives with bounded input handling and redacted findings.
- Added LangGraph routing for scan execution and security knowledge questions.
- Added optional Qdrant retrieval for document-backed RAG answers and finding evidence references.
- Added guarded PostgreSQL Text2SQL queries with an allowlisted schema, read-only role, row limit, and statement timeout.
- Added CLI, FastAPI, and Streamlit interfaces with health checks and report retrieval.
- Added JSON, Markdown, and SARIF 2.1.0 reporting with repository-relative source locations.
- Added unit, integration, end-to-end, and container runtime tests.
- Added CI quality, full-suite, dependency audit, container build, and self-scan workflows.
