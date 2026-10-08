# Changelog

## 0.1.0

- Added deterministic static scanning for files, directories, and ZIP archives with bounded input handling and redacted findings.
- Added LangGraph routing for scan execution and security knowledge questions.
- Added optional Qdrant retrieval for document-backed RAG answers and finding evidence references.
- Added guarded PostgreSQL Text2SQL queries with an allowlisted schema, read-only role, row limit, and statement timeout.
- Added CLI, FastAPI, and Streamlit interfaces with health checks and report retrieval.
- Added JSON, Markdown, and SARIF 2.1.0 reporting with repository-relative source locations.
- Added unit, integration, end-to-end, and container runtime tests.
- Added CI quality, full-suite, dependency audit, container build, and self-scan workflows.
