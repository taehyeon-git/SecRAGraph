# SecRAGraph DevSecOps and Portfolio Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden SecRAGraph for reproducible delivery, add observability and CI security gates, document provenance and architecture, and publish the verified project as a public GitHub portfolio repository.

**Architecture:** Structured logging and audit events observe the existing application without exposing scanned content. GitHub Actions runs deterministic quality, security, container, and self-scan jobs; the repository documentation explains the RAG and LangGraph design, threat boundaries, original team contribution, and new integration work.

**Tech Stack:** structlog, GitHub Actions, Ruff, mypy, pytest, Bandit, pip-audit, Docker Compose, SARIF, GitHub CLI

**Spec:** `docs/superpowers/specs/2026-09-20-sec-ragraph-design.md`

## Global Constraints

- Complete the core-scanner, API-persistence, and intelligence-LangGraph plans first.
- No workflow, image layer, log, fixture, report, or repository file may contain a working credential.
- Containers run as a non-root user and receive secrets only at runtime.
- CI tests do not require OpenAI, Supabase, or Qdrant Cloud credentials.
- The public README must identify the original team project, individual project, and new integration work separately.
- GitHub Actions must use least-privilege permissions; SARIF upload receives `security-events: write` only in its job.

## Review Focus

- A secret-like match in scanned content must not appear in JSON logs or audit payloads; Task 1 pins this behavior.
- Pull requests from forks must run the self-scan without failing on unavailable SARIF-upload permission; Task 3 pins this behavior.
- A dependency-audit network failure must be distinguishable from a discovered vulnerability and must not be silently treated as success; Task 2 pins this behavior.
- The production image must run as non-root and write only to declared temporary locations; Task 4 pins this behavior.
- Attribution text and Git commit identity must map to the user's GitHub account before the first public push; Tasks 5 and 6 pin this behavior.

---

### Task 1: Structured logging, correlation IDs, and audit events

**Files:**
- Modify: `pyproject.toml`
- Create: `src/security_review/observability.py`
- Create: `src/security_review/audit.py`
- Create: `src/security_review/storage/audit.py`
- Modify: `src/security_review/api/app.py`
- Modify: `src/security_review/orchestrator/knowledge_graph.py`
- Modify: `src/security_review/orchestrator/scan_graph.py`
- Test: `tests/unit/test_observability.py`
- Test: `tests/unit/test_audit.py`
- Test: `tests/integration/storage/test_audit_events.py`

**Interfaces:**
- Consumes: request metadata, scan IDs, graph route names, retry counts, dependency states, and safe aggregate counts.
- Produces: `configure_logging(environment: str)`, `bind_context(correlation_id: str, scan_id: str | None)`, `AuditEvent`, `AuditSink.record(event: AuditEvent) -> None`, and `PostgresAuditSink`.

- [ ] **Step 1: Add structured logging dependency**

Run: `uv add structlog`
Expected: `structlog` is locked without changing the Python floor.

- [ ] **Step 2: Write failing redaction and correlation tests**

```python
def test_logs_exclude_scanned_secret(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("test")
    secret = "sk-live-value-that-must-not-appear"
    log_scan_completed(scan_id="scan-1", counts={"high": 1}, raw_match=secret)
    output = capsys.readouterr().out
    assert secret not in output
    assert "scan-1" in output


def test_request_reuses_incoming_correlation_id(client: TestClient) -> None:
    response = client.get("/health/live", headers={"X-Correlation-ID": "test-correlation"})
    assert response.headers["X-Correlation-ID"] == "test-correlation"
```

Also test invalid correlation IDs are replaced, exception responses include the generated ID, and audit events reject keys named `source`, `content`, `prompt`, `token`, `password`, or `secret`.

Run: `uv run pytest tests/unit/test_observability.py tests/unit/test_audit.py -v`
Expected: FAIL because observability modules do not exist.

- [ ] **Step 3: Implement allowlisted structured events**

```python
class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True)
    event_type: Literal[
        "scan_started",
        "scan_completed",
        "route_selected",
        "retry_performed",
        "dependency_failed",
    ]
    correlation_id: str
    scan_id: str | None = None
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def reject_sensitive_keys(cls, value: dict[str, object]) -> dict[str, object]:
        blocked = {"source", "content", "prompt", "token", "password", "secret"}
        if blocked.intersection(key.lower() for key in value):
            raise ValueError("audit attributes contain a sensitive key")
        return value
```

Render JSON in containers/production and concise console logs in development. Log only counts, durations, rule IDs, route names, and typed failures; never pass finding evidence or questions to the logger.

Implement `PostgresAuditSink` against the existing `app.audit_events` table. It stores the event type, correlation/scan IDs, safe JSON attributes, and timestamp. Add an integration test that records and reloads every event type, then verifies none of the persisted JSON keys can contain the blocked sensitive names.

Run: `uv run pytest tests/unit/test_observability.py tests/unit/test_audit.py tests/integration/storage/test_audit_events.py -v`
Expected: PASS.

- [ ] **Step 4: Commit observability**

```bash
git add pyproject.toml uv.lock src/security_review/observability.py src/security_review/audit.py src/security_review/storage/audit.py src/security_review/api/app.py src/security_review/orchestrator tests/unit/test_observability.py tests/unit/test_audit.py tests/integration/storage/test_audit_events.py
git commit -m "feat: add privacy-safe observability"
```

### Task 2: Deterministic quality and dependency-security workflow

**Files:**
- Modify: `pyproject.toml`
- Create: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`
- Create: `scripts/ci_dependency_audit.py`
- Test: `tests/unit/scripts/test_ci_dependency_audit.py`

**Interfaces:**
- Consumes: locked dependencies and the full unit/integration test suite.
- Produces: separate `quality`, `tests`, `dependency-security`, and `container-build` CI jobs.

- [ ] **Step 1: Add security development tools and a tested audit wrapper**

Run:

```bash
uv add --dev bandit pip-audit
```

Create a wrapper that executes `pip-audit --strict --desc --format json`, parses its JSON, exits `1` when vulnerabilities are reported, and exits `2` with `audit_unavailable` when the tool cannot reach its advisory source. Do not convert exit `2` to success.

```python
def test_network_failure_is_not_reported_as_clean() -> None:
    result = classify_audit_result(returncode=2, stdout="", stderr="connection timeout")
    assert result.status == "audit_unavailable"
    assert result.exit_code == 2
```

Run: `uv run pytest tests/unit/scripts/test_ci_dependency_audit.py -v`
Expected: PASS after the wrapper is implemented.

- [ ] **Step 2: Create the least-privilege quality workflow**

Use concurrency cancellation, `contents: read` at workflow level, Python 3.11, `uv sync --frozen --dev`, and the current immutable setup-uv commit.

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4 # v10.1.0
        with:
          version: "0.12.12"
      - run: uv python install 3.11
      - run: uv sync --frozen --dev
      - run: uv run ruff format --check .
      - run: uv run ruff check .
      - run: uv run mypy src apps
      - run: uv run bandit -q -r src apps
```

Add a test job with PostgreSQL and Qdrant service containers, migrations, sample ingestion, unit/integration tests, and coverage XML. Add a dependency-security job that runs the wrapper. Add a container-build job that runs only after quality and tests.

- [ ] **Step 3: Configure weekly dependency updates**

Configure Dependabot for `pip`, `github-actions`, and `docker`, weekly, with a maximum of five open PRs per ecosystem and grouped patch/minor updates. Do not group major updates.

- [ ] **Step 4: Validate the workflow locally**

Run: `uv run ruff check .`
Expected: PASS.

Run: `uv run mypy src apps`
Expected: PASS.

Run: `uv run pytest --cov=security_review --cov-report=term-missing`
Expected: PASS.

Run: `uv run bandit -q -r src apps`
Expected: PASS or only explicitly documented, line-specific false-positive exclusions.

Run: `uv run python scripts/ci_dependency_audit.py`
Expected: exit 0 with no known vulnerable locked dependency; vulnerability and unavailable states use distinct nonzero exits.

- [ ] **Step 5: Commit CI quality gates**

```bash
git add pyproject.toml uv.lock .github/workflows/ci.yml .github/dependabot.yml scripts/ci_dependency_audit.py tests/unit/scripts
git commit -m "ci: add quality and dependency security gates"
```

### Task 3: Self-scan SARIF workflow and fork-safe Code Scanning upload

**Files:**
- Create: `.github/workflows/security-scan.yml`
- Create: `scripts/validate_sarif.py`
- Test: `tests/unit/scripts/test_validate_sarif.py`

**Interfaces:**
- Consumes: installed `security-review` CLI and the repository source tree.
- Produces: `build/secragraph.sarif` on every push/PR and uploads it to GitHub Code Scanning only when token permissions permit.

- [ ] **Step 1: Write a failing SARIF validation test**

```python
def test_validator_rejects_absolute_artifact_uri(tmp_path: Path) -> None:
    sarif = make_sarif(uri="C:/workspace/app.py")
    path = tmp_path / "result.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")
    result = validate_sarif(path)
    assert result.errors == ("artifact URI must be relative: C:/workspace/app.py",)
```

Also test schema version, required driver name, unique fingerprints, one-based regions, and absence of the controlled fake secret.

Run: `uv run pytest tests/unit/scripts/test_validate_sarif.py -v`
Expected: FAIL because the validator does not exist.

- [ ] **Step 2: Implement the local validator and generate a clean report**

Run:

```bash
uv run security-review scan src --format sarif --output build/secragraph.sarif
uv run python scripts/validate_sarif.py build/secragraph.sarif
```

Expected: validator exits 0; findings may exist, but every location is relative and every fingerprint is stable.

- [ ] **Step 3: Create the fork-safe workflow**

```yaml
permissions:
  contents: read

jobs:
  self-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4 # v10.1.0
        with:
          version: "0.12.12"
      - run: uv python install 3.11
      - run: uv sync --frozen
      - run: uv run security-review scan src --format sarif --output build/secragraph.sarif
      - run: uv run python scripts/validate_sarif.py build/secragraph.sarif
      - name: Upload SARIF
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: build/secragraph.sarif
```

Grant `security-events: write` only to this job. The generation and validation steps still run on fork pull requests; only upload is skipped.

- [ ] **Step 4: Commit self-scanning Code Scanning integration**

```bash
git add .github/workflows/security-scan.yml scripts/validate_sarif.py tests/unit/scripts/test_validate_sarif.py
git commit -m "ci: publish SecRAGraph SARIF results"
```

### Task 4: Container hardening and reproducibility checks

**Files:**
- Modify: `Dockerfile`
- Modify: `compose.yaml`
- Modify: `.dockerignore`
- Create: `tests/integration/container/test_runtime.py`
- Create: `docs/operations.md`

**Interfaces:**
- Consumes: locked Python environment and runtime settings.
- Produces: non-root, health-checked API and Streamlit images with declared writable temp paths and documented operations.

- [ ] **Step 1: Write failing runtime identity and filesystem tests**

```python
def test_api_container_is_non_root(compose: ComposeRunner) -> None:
    result = compose.exec("api", ["id", "-u"])
    assert result.stdout.strip() not in {"0", ""}


def test_api_can_scan_with_read_only_root_filesystem(compose: ComposeRunner) -> None:
    response = requests.post(
        f"{compose.api_url}/v1/scans/file",
        files={"file": ("app.py", b"eval(user_input)", "text/x-python")},
        timeout=10,
    )
    assert response.status_code == 200
```

Run: `uv run pytest tests/integration/container/test_runtime.py -v -m integration`
Expected: FAIL until container restrictions and temp mounts are configured.

- [ ] **Step 2: Harden build and runtime**

Use a pinned Python 3.11 slim digest recorded in the Dockerfile comment, install dependencies from `uv.lock`, omit compilers and caches from the final stage, set `PYTHONDONTWRITEBYTECODE=1`, run as an unprivileged numeric UID, and declare `/tmp/secragraph` as the upload workspace.

Set `read_only: true`, `tmpfs: [/tmp/secragraph]`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and resource limits for API and web services. PostgreSQL and Qdrant retain only their named data volumes.

- [ ] **Step 3: Verify reproducible startup and graceful shutdown**

Run: `docker compose build --no-cache api web`
Expected: images build from the lockfile.

Run: `docker compose up -d`
Expected: all services become healthy.

Run: `uv run pytest tests/integration/container/test_runtime.py -v -m integration`
Expected: PASS as non-root with a read-only root filesystem.

Run: `docker compose stop api`
Expected: the API exits within the configured grace period with no corrupted report transaction.

- [ ] **Step 4: Document startup, backup, migration, and incident checks**

Document exact commands for Compose startup, migrations, sample data import, Qdrant ingestion, health inspection, log inspection, Postgres backup, and removal of local demo volumes. Clearly label volume deletion as destructive.

- [ ] **Step 5: Commit container hardening**

```bash
git add Dockerfile compose.yaml .dockerignore tests/integration/container docs/operations.md
git commit -m "chore: harden SecRAGraph containers"
```

### Task 5: Portfolio README, architecture, threat model, and provenance

**Files:**
- Create: `README.md`
- Create: `LICENSE`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `docs/architecture.md`
- Create: `docs/threat-model.md`
- Create: `docs/text2sql-security.md`
- Create: `docs/origins-and-credits.md`
- Create: `docs/demo.md`
- Create: `docs/images/.gitkeep`
- Test: `tests/unit/docs/test_documentation.py`

**Interfaces:**
- Consumes: verified commands, API routes, graph node names, report examples, source repository links, and actual contributor identity.
- Produces: a Korean-first portfolio README with English technical identifiers and independently verifiable setup instructions.

- [ ] **Step 1: Write documentation contract tests**

```python
def test_readme_has_required_portfolio_sections() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    for heading in (
        "## 문제 정의",
        "## 핵심 아키텍처",
        "## LangGraph 워크플로",
        "## RAG와 Text2SQL",
        "## 빠른 시작",
        "## 테스트와 CI",
        "## 한계",
        "## 출처와 기여",
    ):
        assert heading in readme


def test_origin_repositories_are_linked() -> None:
    credits = Path("docs/origins-and-credits.md").read_text(encoding="utf-8")
    assert "https://github.com/ye11an9/rag-documents" in credits
    assert "https://github.com/taehyeon-git/security-agent-langgraph" in credits
```

Also test that every documented local command exists in the CLI help, referenced local files exist, and neither docs nor examples match live-key patterns.

Run: `uv run pytest tests/unit/docs/test_documentation.py -v`
Expected: FAIL because portfolio docs do not exist.

- [ ] **Step 2: Write the README around evaluator outcomes**

Lead with one sentence: SecRAGraph statically reviews source code, routes security intelligence through LangGraph, and grounds remediation in PostgreSQL CVE/CWE data and Qdrant RAG evidence. Follow with a short redacted output example, architecture diagram, five-minute Compose quick start, API/CLI calls, graph explanation, CI/SARIF evidence, limitations, and links to deeper documents.

Do not claim professional SAST replacement, automatic remediation, production multi-tenancy, or benchmark accuracy that has not been measured.

- [ ] **Step 3: Document provenance and new work precisely**

`docs/origins-and-credits.md` must state:

- `rag-documents` was a team education project and link its contributors page.
- `security-agent-langgraph` was the individual security-agent exercise.
- SecRAGraph newly adds shared domain contracts, safe upload handling, FastAPI, persistence, guarded Text2SQL, Qdrant adapter boundaries, two LangGraph workflows, JSON/Markdown/SARIF reports, tests, containers, and CI.
- Third-party documents are not redistributed without permission; ingestion is user-operated.

Choose an MIT license for newly authored SecRAGraph code only. Explain that source-project code and data remain subject to their original rights and attribution.

- [ ] **Step 4: Document trust boundaries and decisions**

The threat model covers uploaded code, ZIP archives, secret evidence, prompt injection, model output, generated SQL, databases, logs, CI tokens, and cloud-provider credentials. The architecture document names every module and interface. The Text2SQL document records the read-only role, AST validation, allowlist, limit, timeout, and retry boundary.

Run: `uv run pytest tests/unit/docs/test_documentation.py -v`
Expected: PASS.

- [ ] **Step 5: Commit portfolio documentation**

```bash
git add README.md LICENSE SECURITY.md CONTRIBUTING.md docs tests/unit/docs
git commit -m "docs: present SecRAGraph portfolio"
```

### Task 6: Final verification and public GitHub release

**Files:**
- Modify: `docs/demo.md` after capturing verified output.
- Create: `CHANGELOG.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/pull_request_template.md`

**Interfaces:**
- Consumes: the complete repository and authenticated GitHub CLI.
- Produces: `https://github.com/taehyeon-git/SecRAGraph` on `main`, with passing CI and a tagged `v0.1.0` release only after all checks pass.

- [ ] **Step 1: Verify Git identity before public history is pushed**

Run: `gh auth status`
Expected: authenticated as `taehyeon-git` with repository creation permission.

Run: `gh api user --jq '{login: .login, id: .id}'`
Expected: login is exactly `taehyeon-git` and the numeric account ID is returned.

Set this repository's local email to `<ID>+taehyeon-git@users.noreply.github.com`, leaving global Git configuration unchanged. Inspect `git log --format='%h %an <%ae>'`; any pre-publication commit with the accidental `gamil.com` address must be corrected only after explicit confirmation because that rewrites local history.

- [ ] **Step 2: Run the complete release gate from a clean checkout state**

Run: `git status --short`
Expected: empty.

Run: `uv sync --frozen --dev`
Expected: no lockfile change.

Run: `uv run ruff format --check .`
Expected: PASS.

Run: `uv run ruff check .`
Expected: PASS.

Run: `uv run mypy src apps`
Expected: PASS.

Run: `uv run pytest --cov=security_review --cov-report=term-missing`
Expected: PASS.

Run: `uv run bandit -q -r src apps`
Expected: PASS.

Run: `uv run python scripts/ci_dependency_audit.py`
Expected: exit 0.

Run: `docker compose config`
Expected: PASS without secret values printed.

Run: `docker compose up -d --build`
Expected: all four services healthy.

Run: `uv run pytest tests/integration tests/e2e -v`
Expected: PASS.

Run: `uv run security-review scan src --format sarif --output build/secragraph.sarif`
Expected: a redacted SARIF 2.1.0 file.

Run: `uv run python scripts/validate_sarif.py build/secragraph.sarif`
Expected: PASS.

- [ ] **Step 3: Create release metadata and commit it**

Write `CHANGELOG.md` with a `0.1.0` section listing deterministic scanning, LangGraph routing, RAG, Text2SQL controls, APIs, reporting, tests, and CI. Add issue and PR templates that request reproducible steps without requesting secrets or private source files.

```bash
git add CHANGELOG.md .github/ISSUE_TEMPLATE .github/pull_request_template.md docs/demo.md
git commit -m "chore: prepare SecRAGraph v0.1.0"
```

- [ ] **Step 4: Confirm the remote name is available before creation**

Run: `gh repo view taehyeon-git/SecRAGraph --json name,url,visibility`
Expected: repository-not-found. If it exists, stop and inspect it rather than overwriting or force-pushing.

- [ ] **Step 5: Create and push the public repository**

Run:

```bash
gh repo create taehyeon-git/SecRAGraph --public --source . --remote origin --push --description "RAG and LangGraph powered security review platform"
```

Expected: `origin` points to `https://github.com/taehyeon-git/SecRAGraph.git`, `main` is pushed, and the repository URL is returned.

- [ ] **Step 6: Verify GitHub Actions before tagging**

Run: `gh run list --repo taehyeon-git/SecRAGraph --limit 10`
Expected: CI and security-scan workflows appear.

Run: `gh run watch --repo taehyeon-git/SecRAGraph --exit-status`
Expected: the selected latest run completes successfully. If multiple workflows are pending, inspect and watch each run ID rather than assuming success.

- [ ] **Step 7: Tag and publish the verified release**

Run: `git tag -s v0.1.0 -m "SecRAGraph v0.1.0"`
Expected: a signed tag is created when a signing key is configured. If signing is unavailable, stop and ask whether to create an unsigned annotated tag.

Run: `git push origin v0.1.0`
Expected: tag is pushed without force.

Run: `gh release create v0.1.0 --repo taehyeon-git/SecRAGraph --generate-notes --title "SecRAGraph v0.1.0"`
Expected: a public release URL is returned.

- [ ] **Step 8: Record final public evidence**

Add the actual CI badge and release link to README only after both URLs exist. Capture redacted API, LangGraph Studio, Streamlit, and Code Scanning screenshots into `docs/images`, rerun documentation tests, commit, and push normally.

```bash
git add README.md docs/images docs/demo.md
git commit -m "docs: add verified SecRAGraph demo evidence"
git push origin main
```

Expected: public README renders correctly, all links resolve, Code Scanning shows the uploaded SecRAGraph SARIF category, and the final CI run passes.
