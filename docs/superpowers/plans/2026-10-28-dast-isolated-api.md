# Isolated API DAST Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run bounded passive DAST against a labelled disposable API container and produce LangGraph-enriched JSON, Markdown and SARIF reports with honest HTTP locations.

**Architecture:** A Docker network boundary restricts ZAP to one test container. The ZAP adapter normalizes HTTP findings into the canonical report with a distinct location type, and the existing graph adds evidence and renders outputs. CI scans a disposable fixture and publishes only sanitized results.

**Tech Stack:** Python 3.11, Pydantic 2, LangGraph, Alembic/PostgreSQL, Typer, Docker, OWASP ZAP API scan.

**Spec:** `docs/design/dast-isolated-api.md`

## Global Constraints

- No DAST URL endpoint in the member API; never execute uploaded source.
- Require `io.secragraph.dast.disposable=true` on the Docker target.
- Use a dedicated Docker `--internal` network and guarantee named ZAP container/network cleanup after every failure.
- Fetch OpenAPI through a named, short-lived helper container on the internal network with byte/time caps; sanitize before invoking ZAP: local schema, target-only server, GET/HEAD/OPTIONS only, no external `$ref`.
- DAST mode in this phase is ZAP `zap-api-scan.py -S`; report it as passive.
- Never persist raw ZAP JSON, request bodies, query strings, or authentication headers.
- HTTP findings must not claim a source file location in JSON, Markdown, or SARIF.
- DAST SARIF is a separate artifact with logical HTTP locations, not a GitHub Code Scanning source annotation.

## Review Focus

- A target container without the disposable label is rejected before a network is created.
- An OpenAPI spec that points outside the isolated target cannot produce accepted off-origin findings.
- A malformed report or ZAP failure is reported as incomplete/error, never completed with zero findings.
- A token appearing in ZAP evidence, headers, or URL query is absent from every saved report and console output.
- Cleanup runs after timeout, nonzero exit, parse failure, and success.
- A targetless LangGraph invocation keeps DAST findings, warnings and execution status under a bounded enrichment deadline.

---

### Task 1: Typed HTTP locations and persistence

**Files:** `src/security_review/domain/models.py`, `src/security_review/reporting/{builder,markdown,sarif}.py`, `src/security_review/storage/models.py`, `src/security_review/scanner/external_detectors.py`, `src/security_review/intelligence/dependency_osv.py`, `migrations/versions/20261028_0007_http_findings.py`, and matching unit/integration tests.

**Interfaces:** `Finding` adds optional `http_method` and `http_path` and requires exactly one of source and HTTP location. `ScanExecution.kind` adds `dast`, with validated `eligible_endpoints` and `observed_alert_endpoints`. Existing source finding constructors and report shapes remain valid.

- [ ] Add failing tests for mutually exclusive locations, bounded HTTP paths, endpoint coverage labels, mixed source/HTTP ordering and PostgreSQL round-trip, Markdown and logical SARIF rendering.
- [ ] Run focused tests and verify missing behavior fails.
- [ ] Implement model, renderers, ORM mapper and reversible migration; narrow source-only scanner/OSV path collections after making `file_path` optional.
- [ ] Run focused tests, Ruff and mypy; commit the independently tested change.

### Task 2: ZAP result parser and isolated Docker runner

**Files:** `src/security_review/dast/{zap,runner}.py`, `tests/unit/dast/test_zap.py`, `tests/unit/dast/test_runner.py`.

**Interfaces:** `run_zap_api_scan(container: str, port: int, openapi_path: str, *, auth_header_env: str | None = None) -> DastScanResult`; result contains findings, warnings and `ScanExecution`. Before ZAP, fetch and sanitize a bounded OpenAPI document; parse a bounded Traditional JSON document and discard raw evidence.

- [ ] Add failing schema/parser tests for external servers/refs, unsafe methods, normal alerts, duplicate instances, host mismatch, malformed/oversized data, query/token redaction and ZAP exit statuses.
- [ ] Add failing runner tests for label refusal, internal-network helper/ZAP commands, bounded helper output and timeout, name-only authentication environment, named helper/ZAP force-removal, every cleanup path and timeout.
- [ ] Implement the parser and runner with a digest-pinned official ZAP image.
- [ ] Run focused tests, Ruff and mypy; commit.

### Task 3: LangGraph and CLI delivery

**Files:** `src/security_review/orchestrator/scan_graph.py`, `src/security_review/cli.py`, `tests/unit/orchestrator/test_scan_graph.py`, `tests/unit/cli/test_dast.py`.

**Interfaces:** The existing graph accepts `findings`, `warnings`, `executions`, and a bounded enrichment budget when no source target is supplied. `security-review dast` runs Task 2, invokes the graph and supports `--format` and `--output` as the source command does.

- [ ] Add failing tests for preserved DAST warnings/execution and partial status, bounded enrichment, CWE enrichment preserving HTTP location and its protected-field invariants, and CLI report/error behavior.
- [ ] Implement the graph input and command; preserve existing source scan behavior.
- [ ] Run focused tests, Ruff and mypy; commit.

### Task 4: Disposable fixture, CI evidence and documentation

**Files:** `apps/dast_fixture/main.py`, `infra/dast/compose.yaml`, `scripts/run_dast_evidence.py`, `.github/workflows/ci.yml`, `README.md`, `docs/demo.md`, plus script tests.

**Interfaces:** One script starts a random isolated fixture project, waits for health, calls the same DAST application function used by CLI **once**, asserts expected passive finding and scope plus authenticated protected-route traffic, renders the resulting single `ScanReport` to JSON/Markdown/SARIF, and tears down the fixture on all paths. CI runs it as a separate job whose failure fails the workflow and uploads normalized artifacts.

- [ ] Add failing script tests for startup/readiness, token non-disclosure, assertions, and teardown.
- [ ] Implement fixture and script; add CI job and truthful docs.
- [ ] Run the full unit suite, live Docker DAST, full quality checks, and any feasible integration tests.
- [ ] Request independent code review, repair findings, rerun gates, and commit.
