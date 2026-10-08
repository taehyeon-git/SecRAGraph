# SecRAGraph Implementation Sequence

The approved design is implemented through four plans. Each phase leaves a working, independently testable deliverable.

1. [`2026-09-20-secragraph-core-scanner.md`](2026-09-20-secragraph-core-scanner.md) — deterministic scanner, domain models, CLI, and JSON/Markdown/SARIF reporting.
2. [`2026-09-20-secragraph-api-persistence.md`](2026-09-20-secragraph-api-persistence.md) — secure uploads, FastAPI, PostgreSQL persistence, and the initial Compose stack.
3. [`2026-09-20-secragraph-intelligence-langgraph.md`](2026-09-20-secragraph-intelligence-langgraph.md) — guarded Text2SQL, Qdrant RAG, LangGraph knowledge and scan workflows, and Streamlit.
4. [`2026-09-20-secragraph-devsecops-portfolio.md`](2026-09-20-secragraph-devsecops-portfolio.md) — observability, CI, self-scan SARIF, container hardening, portfolio documentation, and public GitHub release.

All plans implement [`../specs/2026-09-20-sec-ragraph-design.md`](../specs/2026-09-20-sec-ragraph-design.md).
