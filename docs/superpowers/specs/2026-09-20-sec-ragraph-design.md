# SecRAGraph Design

Status: Approved for implementation planning
Date: 2026-09-20
Repository: `SecRAGraph`

## 1. Purpose

SecRAGraph combines two education projects into one RAG- and LangGraph-focused security portfolio project with production-oriented backend and DevSecOps delivery:

- [`ye11an9/rag-documents`](https://github.com/ye11an9/rag-documents): the team project that provides security-document RAG, CVE/CWE Text2SQL, query rewriting, and evidence-backed answers.
- [`taehyeon-git/security-agent-langgraph`](https://github.com/taehyeon-git/security-agent-langgraph): the security agent that provides source/configuration-file inspection, sensitive-information detection, middleware, and risk assessment.

The integrated project will accept source files, ZIP archives, or local directories; find deterministic security issues without executing target code; enrich findings with CWE/CVE and document evidence; and emit JSON, Markdown, and SARIF reports through a shared engine used by FastAPI, a CLI, Streamlit, and GitHub Actions.

The README must distinguish the original team work, the original individual work, and the new integration work. It must credit the original team repository and contributors rather than presenting all inherited work as newly authored.

## 2. Goals

1. Demonstrate production-oriented Python backend structure around LangGraph and security analysis.
2. Demonstrate a reproducible DevSecOps workflow with containers, automated tests, dependency checks, static analysis, and SARIF output.
3. Preserve the strongest features of both source projects while replacing notebook- or demo-specific coupling with explicit service boundaries.
4. Produce evidence-backed reports that remain useful when the LLM or vector store is unavailable.
5. Make the default local environment reproducible with Docker Compose and no dependency on Supabase or Qdrant Cloud.

## 3. Non-goals

- Executing, importing, compiling, or sandbox-running submitted code.
- Replacing a professional SAST, secret scanner, container scanner, or penetration test.
- Cloning arbitrary remote repository URLs from the API.
- Automatically modifying user code.
- Supporting every programming language or vulnerability class in the first release.
- Providing multi-tenant production authentication or billing.

## 4. Users and Primary Scenarios

### Backend/DevSecOps evaluator

An interviewer can start the stack, inspect the OpenAPI contract, scan an intentionally insecure sample, retrieve the report in three formats, and inspect CI evidence.

### Developer using the CLI

A developer runs `security-review scan <path>` against a local file or directory and receives a local report without uploading the repository to a server.

### CI pipeline

GitHub Actions checks out a repository, invokes the same CLI engine, saves JSON and Markdown artifacts, and uploads SARIF when GitHub Code Scanning is available.

### Security knowledge user

A user asks a CVE/CWE or security-standard question. LangGraph routes structured questions to read-only Text2SQL and document questions to RAG, then returns sources with the answer.

## 5. System Architecture

```text
FastAPI / CLI / GitHub Actions / Streamlit
                  |
          LangGraph Orchestrator
           +------+-------+
           |              |
     Source Scan      Security Q&A
           |              |
Static rules/secrets   RAG / Text2SQL
           |              |
           +-- CWE/CVE evidence --+
                                    |
                        Risk and Report Pipeline
                                    |
                         JSON / Markdown / SARIF
```

The project is a modular monolith. Domain and application logic live in `src/security_review`; delivery mechanisms in `apps` call that logic through stable interfaces. PostgreSQL and Qdrant are separate infrastructure adapters, not dependencies imported into domain code.

## 6. Components

### 6.1 Domain

Defines validated models and policies without FastAPI, LangGraph, SQLAlchemy, or Qdrant imports. It owns `Finding`, `SourceReference`, `ScanReport`, risk levels, scan status, and risk-scoring rules.

### 6.2 Scanner

Reads supported source and configuration files as text, applies deterministic rules, redacts evidence, and returns normalized findings. The scanner never executes target code or shell commands. Initial rules cover hard-coded secret patterns and high-signal Python or configuration risks already demonstrated by the individual security-agent project.

### 6.3 Intelligence

Provides two explicit ports:

- `SecurityKnowledgeRepository` for read-only CVE/CWE relational queries.
- `SecurityDocumentRetriever` for Qdrant similarity search over embedded security documents.

Text2SQL output is parsed before execution, limited to a single read-only `SELECT`, restricted to approved schemas/tables, given a statement timeout, and capped by row count. RAG results include document identity, page or section metadata when present, and similarity metadata.

### 6.4 Orchestrator

LangGraph coordinates application steps; it does not contain low-level scan, SQL, or vector-store implementation details.

Scan path:

```text
validate_input -> deterministic_scan -> normalize_and_deduplicate
-> map_cwe -> retrieve_evidence -> calculate_risk -> build_report
```

Knowledge path:

```text
classify_intent -> general_answer | text2sql | vector_search
text2sql -> validate_sql -> execute_read_only -> answer
vector_search -> evaluate_results -> answer | rewrite_query
```

SQL regeneration and RAG query rewriting have fixed retry limits. A completed deterministic scan does not fail merely because enrichment failed.

### 6.5 Reporting

Transforms one canonical `ScanReport` into:

- JSON for APIs and machine consumption.
- Markdown for people and CI artifacts.
- SARIF 2.1.0 for GitHub Code Scanning.

Each output uses the same finding identifiers, severity mapping, paths, lines, remediations, and references.

### 6.6 Storage

PostgreSQL stores scan metadata, findings, reports, CVE/CWE structured data, and audit events. Application data and security-intelligence data use separate schemas. Text2SQL connects with a read-only role that can access only the approved intelligence schema.

Qdrant stores document chunks and embeddings. Collection names and embedding dimensions are configuration, and the application verifies compatibility at startup. Local Docker services are the default; Supabase and Qdrant Cloud use the same adapters through environment configuration.

The LLM and embedding model names are runtime configuration rather than hard-coded architecture decisions. With no provider credentials, deterministic scanning and local report generation remain available; provider-dependent knowledge queries return a typed unavailable response.

### 6.7 Delivery Interfaces

- FastAPI exposes versioned REST endpoints and OpenAPI documentation.
- A Typer CLI scans local paths and renders or saves reports.
- Streamlit calls the API and remains a thin demonstration client.
- GitHub Actions invokes the CLI instead of maintaining separate scanning logic.

## 7. API Contract

Initial endpoints:

- `GET /health/live`: confirms the process is running.
- `GET /health/ready`: reports PostgreSQL and Qdrant readiness without exposing credentials.
- `POST /v1/scans/file`: scans one supported uploaded file.
- `POST /v1/scans/archive`: scans a validated ZIP archive.
- `GET /v1/scans/{scan_id}`: returns the canonical persisted report as JSON.
- `GET /v1/scans/{scan_id}/report?format=markdown|sarif`: returns a generated representation.
- `POST /v1/knowledge/query`: answers a CVE/CWE or security-document question with sources.

Scan endpoints are synchronous in the first release and enforce conservative upload and processing limits. Durable background jobs and a queue are deliberately deferred until scan duration or concurrency demonstrates the need.

## 8. Domain Models

### Finding

Required fields:

- `id`: stable deterministic identifier within a scan.
- `rule_id`: stable rule identifier.
- `category`: secret, code pattern, configuration, or dependency.
- `severity`: info, low, medium, high, or critical.
- `file_path`: normalized relative path.
- `line_start` and optional `line_end`.
- `message`: concise issue description.
- `redacted_evidence`: non-secret evidence with sensitive values masked.
- `confidence`: low, medium, or high.
- `cwe_ids`: zero or more normalized CWE identifiers.
- `remediation`: concrete defensive recommendation.
- `references`: zero or more `SourceReference` values.

### ScanReport

Required fields:

- `scan_id` and timestamps.
- `status`: completed or completed_with_warnings.
- target metadata that does not include submitted source contents.
- summary counts by severity and category.
- deterministic risk score and risk level.
- ordered findings.
- enrichment warnings.
- tool and rule-set versions.

## 9. Input Validation and Security Boundaries

- API input supports one file or ZIP archive; CLI input supports a local file or directory.
- Remote repository cloning is excluded from the API.
- File size, archive size, extracted size, file count, extension, and processing-time limits are configurable with safe defaults.
- ZIP extraction rejects absolute paths, parent traversal, duplicate normalized paths, links, and unsupported file types.
- Scanner reads bounded text and skips binary content.
- Uploaded content is stored only in a per-request temporary directory and removed after processing.
- Sensitive matches are masked before entering logs, database values, prompts, or reports.
- The service does not execute target code, invoke package managers, or run target-provided scripts.
- Text2SQL uses a separate read-only database credential, an allowlist, parsed statement validation, row limits, and statement timeouts.
- Prompts and retrieved documents are treated as untrusted data. Retrieved instructions cannot override the system workflow or tool permissions.

## 10. Failure Handling

- Invalid input returns a typed 4xx response with a stable error code.
- PostgreSQL unavailability makes scan persistence and knowledge SQL unavailable and causes readiness to fail.
- Qdrant or embedding failure produces `completed_with_warnings` when deterministic scan results exist.
- LLM failure produces a deterministic-only report and never invents enrichment.
- A RAG miss is reported as insufficient evidence; it is not converted into a definitive security claim.
- SQL or retrieval retries are bounded and recorded as structured audit events.
- Unexpected failures use a correlation ID in the response and logs while suppressing stack traces and secrets from client output.

## 11. Observability

Logs are structured JSON in containers and human-readable locally. Every request and scan includes a correlation ID and scan ID. Logs contain lifecycle events, counts, durations, selected route, retry count, and dependency status; they do not contain uploaded source, credentials, raw secret matches, or full prompts.

The initial release exposes health endpoints and records step durations. Prometheus metrics and distributed tracing are extension points, not release blockers.

## 12. Repository Layout

```text
SecRAGraph/
|-- apps/
|   |-- api/
|   `-- web/
|-- src/security_review/
|   |-- domain/
|   |-- scanner/
|   |-- intelligence/
|   |-- orchestrator/
|   |-- reporting/
|   |-- storage/
|   `-- cli.py
|-- migrations/
|-- tests/
|   |-- unit/
|   |-- integration/
|   `-- e2e/
|-- examples/
|-- docs/
|-- infra/
|-- .github/workflows/
|-- Dockerfile
|-- compose.yaml
|-- pyproject.toml
`-- README.md
```

Python 3.11 or later and `uv` manage the environment and lockfile. SQLAlchemy and Alembic manage PostgreSQL access and migrations. Configuration comes from typed environment settings, with a committed `.env.example` containing no secrets.

## 13. DevSecOps and CI

Pull requests and pushes run:

1. Ruff formatting and lint checks.
2. mypy type checks.
3. pytest unit and integration tests with coverage output.
4. Bandit source checks.
5. pip-audit dependency checks.
6. Docker image build.
7. The project's own CLI against controlled insecure examples.
8. SARIF validation and artifact publication; Code Scanning upload is enabled where repository permissions support it.

CI uses mock LLM, embedding, PostgreSQL, and Qdrant adapters for deterministic unit tests. Service-container integration tests verify the real PostgreSQL and Qdrant adapters without requiring OpenAI, Supabase, or cloud credentials. Live-provider tests are manual and opt-in.

The container runs as a non-root user, has a health check, and receives secrets only through runtime environment variables or the deployment platform's secret store.

## 14. Testing Strategy

- Domain unit tests cover risk calculation, severity mapping, deduplication, and model validation.
- Scanner unit tests cover each rule, redaction, binary detection, size limits, and path normalization.
- Archive security tests cover traversal, absolute paths, links, collisions, file-count limits, and compression expansion limits.
- Orchestrator tests use fake ports to cover every route, bounded retry, enrichment failure, and partial-report behavior.
- Reporting tests use golden JSON, Markdown, and SARIF fixtures derived from one canonical report.
- API tests cover success, typed errors, upload limits, content-type handling, and health endpoints.
- Storage integration tests verify migrations, read-only Text2SQL permissions, Qdrant collection checks, and persistence.
- One end-to-end test scans the controlled insecure sample and verifies consistent finding IDs across JSON, Markdown, and SARIF.

## 15. Documentation and Portfolio Presentation

The README leads with the problem and a short demo, not installation details. It includes:

- Architecture diagram and request flows.
- A five-minute Docker Compose quick start.
- API and CLI examples.
- A redacted example finding and report.
- CI and SARIF screenshots after the public repository is active.
- Security model and explicit limitations.
- An "Origins and Credits" section linking both source repositories.
- A "What I added in the integrated project" section listing new domain contracts, API, orchestration, reporting, tests, containers, and CI.

Detailed documents cover architecture decisions, scanner rules, Text2SQL controls, and the threat model.

## 16. Acceptance Criteria

The first portfolio release is complete when:

1. `docker compose up --build` starts FastAPI, PostgreSQL, and Qdrant with passing readiness checks.
2. The CLI and both scan endpoints detect the controlled sample's expected findings without executing it.
3. Each finding is normalized, redacted, risk-scored, and optionally enriched with sourced CWE/CVE or document evidence.
4. One canonical report renders valid JSON, readable Markdown, and SARIF 2.1.0 with consistent finding IDs.
5. Knowledge questions route to general, read-only Text2SQL, or RAG paths and return explicit sources or an insufficient-evidence result.
6. The platform returns a deterministic partial report when LLM or Qdrant enrichment is unavailable.
7. Unit, integration, and end-to-end tests pass locally and in GitHub Actions without cloud secrets.
8. Docker, Bandit, pip-audit, and the project's own scan workflow pass.
9. README attribution accurately identifies the team project, the individual project, and the new integration work.
10. The public GitHub repository contains no credentials, unredacted secret fixtures, or copied third-party documents without appropriate redistribution permission.

## 17. Deferred Extensions

The following are intentionally deferred until after the first portfolio release: authenticated multi-user operation, durable distributed job queues, remote repository cloning, automatic fixes, pull-request comments, Semgrep/Bandit/Trivy result ingestion as first-class adapters, Kubernetes deployment, and PDF report generation.
