# SecRAGraph Core Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, non-executing source scanner with canonical findings, risk scoring, JSON/Markdown/SARIF reporting, and a local CLI.

**Architecture:** Domain models remain independent of delivery and infrastructure libraries. A bounded file-discovery layer feeds a deterministic rule engine, which produces one canonical report rendered by format-specific serializers and invoked by Typer.

**Tech Stack:** Python 3.11+, uv, Pydantic v2, Typer, Rich, pytest, Ruff, mypy

**Spec:** `docs/superpowers/specs/2026-09-20-sec-ragraph-design.md`

## Global Constraints

- Python 3.11 or later; dependencies and lockfile are managed with `uv`.
- Never execute, import, compile, or invoke package-manager commands from scanned content.
- Never place raw secret matches in findings, logs, prompts, or reports.
- Local deterministic scanning must work without OpenAI, PostgreSQL, or Qdrant.
- Paths in reports are normalized relative paths, never host absolute paths.
- Credit both source repositories and distinguish inherited work from new integration work.

## Review Focus

- Binary or invalid UTF-8 input must be skipped with a typed warning instead of crashing; Task 2 pins this behavior.
- A symlink that resolves outside the requested root must not be scanned; Task 2 pins this behavior.
- Secret evidence must be irreversibly redacted before it reaches a `Finding`; Task 3 pins this behavior.
- Finding IDs and ordering must be stable across repeated scans and all output formats; Tasks 4 and 5 pin this behavior.
- An empty result must produce a valid low-risk report rather than a division error or missing summary; Task 1 pins this behavior.

---

### Task 1: Project foundation and domain contracts

**Files:**
- Create: `pyproject.toml`
- Create: `src/security_review/__init__.py`
- Create: `src/security_review/domain/__init__.py`
- Create: `src/security_review/domain/models.py`
- Create: `src/security_review/domain/risk.py`
- Test: `tests/unit/domain/test_models.py`
- Test: `tests/unit/domain/test_risk.py`

**Interfaces:**
- Consumes: no application interfaces.
- Produces: `Severity`, `Confidence`, `ScanStatus`, `SourceReference`, `Finding`, `RiskSummary`, `ReportSummary`, `ScanReport`, `__version__ = "0.1.0"`, and `calculate_risk(findings: Sequence[Finding]) -> RiskSummary`.

- [ ] **Step 1: Add the package and test tool configuration**

Create `pyproject.toml` with installable `src` layout and explicit commands:

```toml
[project]
name = "secragraph"
version = "0.1.0"
description = "RAG- and LangGraph-powered security review platform"
requires-python = ">=3.11"
dependencies = [
  "pydantic>=2,<3",
  "rich>=13,<15",
  "typer>=0.12,<1",
]

[project.scripts]
security-review = "security_review.cli:app"

[dependency-groups]
dev = [
  "mypy>=1.11,<2",
  "pytest>=8,<10",
  "pytest-cov>=5,<8",
  "ruff>=0.8,<1",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/security_review"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "S"]

[tool.ruff.lint.per-file-ignores]
"examples/insecure/*" = ["S"]

[tool.mypy]
python_version = "3.11"
strict = true
packages = ["security_review"]
```

Run: `uv sync --dev`
Expected: `.venv` and `uv.lock` are created with no resolver error.

- [ ] **Step 2: Write failing domain-model and empty-risk tests**

```python
from security_review.domain.models import Finding, Severity
from security_review.domain.risk import calculate_risk


def test_finding_rejects_absolute_path() -> None:
    with pytest.raises(ValueError, match="relative"):
        Finding(
            id="SEC001:abc",
            rule_id="SEC001",
            category="secret",
            severity=Severity.HIGH,
            file_path="C:/private/app.py",
            line_start=1,
            message="Potential secret",
            redacted_evidence="token=***",
            confidence="high",
            remediation="Move the value to a secret store.",
        )


def test_empty_findings_have_zero_low_risk() -> None:
    result = calculate_risk([])
    assert result.score == 0
    assert result.level == Severity.LOW
    assert result.counts == {severity: 0 for severity in Severity}
```

Run: `uv run pytest tests/unit/domain -v`
Expected: FAIL during collection because `security_review.domain` does not exist.

- [ ] **Step 3: Implement immutable domain models and deterministic risk scoring**

Use string enums and frozen Pydantic models. Validate `file_path` with `PurePosixPath`, rejecting absolute paths and `..`. Implement weighted scoring with `INFO=0`, `LOW=1`, `MEDIUM=3`, `HIGH=7`, and `CRITICAL=12`; map totals `0-1` to low, `2-6` to medium, `7-14` to high, and `15+` to critical.

```python
class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    rule_id: str
    category: str
    severity: Severity
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int | None = Field(default=None, ge=1)
    message: str
    redacted_evidence: str
    confidence: Confidence
    cwe_ids: tuple[str, ...] = ()
    remediation: str
    references: tuple[SourceReference, ...] = ()

    @field_validator("file_path")
    @classmethod
    def require_relative_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not path.parts or path.as_posix() == ".":
            raise ValueError("file_path must be relative")
        if path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise ValueError("file_path must be relative")
        return path.as_posix()
```

Run: `uv run pytest tests/unit/domain -v`
Expected: PASS.

- [ ] **Step 4: Run static checks**

Run: `uv run ruff check src tests`
Expected: PASS.

Run: `uv run mypy src`
Expected: PASS.

- [ ] **Step 5: Commit the domain foundation**

```bash
git add pyproject.toml uv.lock src/security_review tests/unit/domain
git commit -m "feat: add core security review domain"
```

### Task 2: Bounded file discovery and safe text reading

**Files:**
- Create: `src/security_review/scanner/__init__.py`
- Create: `src/security_review/scanner/files.py`
- Test: `tests/unit/scanner/test_files.py`

**Interfaces:**
- Consumes: standard-library `Path` values.
- Produces: `ScanLimits`, `ScannableFile`, `SkippedFile`, `DiscoveryResult`, `discover_files(root: Path, limits: ScanLimits) -> DiscoveryResult`, and `read_scannable_text(file: ScannableFile, limits: ScanLimits) -> str | None`.

- [ ] **Step 1: Write failing discovery boundary tests**

```python
def test_binary_file_is_reported_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_bytes(b"print('ok')\x00\xff")
    result = discover_files(target, ScanLimits())
    assert result.files == ()
    assert result.skipped[0].reason == "binary_or_invalid_utf8"


def test_symlink_outside_root_is_not_scanned(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "secret.py"
    outside.write_text("password='outside'", encoding="utf-8")
    link = root / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    result = discover_files(root, ScanLimits())
    assert result.files == ()
    assert result.skipped[0].reason == "symlink"
```

Also test unsupported extensions, a file larger than `max_file_bytes`, deterministic path sorting, and `max_files` enforcement.

Run: `uv run pytest tests/unit/scanner/test_files.py -v`
Expected: FAIL because `scanner.files` does not exist.

- [ ] **Step 2: Implement limits, discovery, and decoding**

```python
@dataclass(frozen=True)
class ScanLimits:
    max_file_bytes: int = 1_000_000
    max_files: int = 500
    max_processing_seconds: float = 30.0
    allowed_extensions: frozenset[str] = frozenset(
        {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env", ".ini"}
    )


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError):
        return False
    return True
```

Walk with `Path.rglob`, reject links before resolving, sort by POSIX relative path, stop at `max_files`, read at most `max_file_bytes + 1`, reject NUL bytes, and decode strictly as UTF-8. Return typed skip reasons rather than raising for individual files.

Run: `uv run pytest tests/unit/scanner/test_files.py -v`
Expected: PASS, including binary and symlink tests.

- [ ] **Step 3: Run scanner-module static checks**

Run: `uv run ruff check src/security_review/scanner tests/unit/scanner`
Expected: PASS.

Run: `uv run mypy src/security_review/scanner`
Expected: PASS.

- [ ] **Step 4: Commit safe file discovery**

```bash
git add src/security_review/scanner tests/unit/scanner
git commit -m "feat: add bounded source discovery"
```

### Task 3: Deterministic rules and secret redaction

**Files:**
- Create: `src/security_review/scanner/rules.py`
- Create: `src/security_review/scanner/redaction.py`
- Create: `src/security_review/scanner/engine.py`
- Test: `tests/unit/scanner/test_engine.py`
- Test: `tests/unit/scanner/test_redaction.py`

**Interfaces:**
- Consumes: `ScannableFile`, decoded source text, and domain `Finding`.
- Produces: `Rule`, `DEFAULT_RULES`, `redact_match(line: str, span: tuple[int, int]) -> str`, and `scan_text(file_path: str, text: str, rules: Sequence[Rule] = DEFAULT_RULES) -> tuple[Finding, ...]`.

- [ ] **Step 1: Write failing redaction and rule tests**

```python
def test_secret_is_absent_from_finding_dump() -> None:
    token = "sk-test-1234567890abcdef"
    findings = scan_text("settings.py", f'OPENAI_API_KEY = "{token}"\n')
    assert len(findings) == 1
    serialized = findings[0].model_dump_json()
    assert token not in serialized
    assert "***REDACTED***" in serialized


@pytest.mark.parametrize(
    ("source", "rule_id", "cwe_id"),
    [
        ("eval(user_input)", "PY001", "CWE-95"),
        ("subprocess.run(cmd, shell=True)", "PY002", "CWE-78"),
        ("requests.get(url, verify=False)", "PY003", "CWE-295"),
    ],
)
def test_python_risk_rules(source: str, rule_id: str, cwe_id: str) -> None:
    finding = scan_text("app.py", source)[0]
    assert finding.rule_id == rule_id
    assert cwe_id in finding.cwe_ids
```

Run: `uv run pytest tests/unit/scanner/test_engine.py tests/unit/scanner/test_redaction.py -v`
Expected: FAIL because the rule engine does not exist.

- [ ] **Step 2: Define immutable rules with explicit metadata**

```python
@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    pattern: Pattern[str]
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    cwe_ids: tuple[str, ...]
    extensions: frozenset[str]
```

Define `SEC001` for assigned secret-like values and the three Python rules from the test. Anchor secret detection to recognized credential names and require a non-placeholder value of at least eight characters to reduce obvious false positives.

- [ ] **Step 3: Implement redaction, stable IDs, and deterministic ordering**

```python
def finding_id(rule_id: str, path: str, line_number: int, redacted: str) -> str:
    payload = f"{rule_id}\0{path}\0{line_number}\0{redacted}".encode()
    return f"{rule_id}:{sha256(payload).hexdigest()[:16]}"
```

Split with `text.splitlines()`, apply rules appropriate to the file extension, redact the exact capture before constructing a finding, and return findings sorted by `(file_path, line_start, rule_id, id)`.

Run: `uv run pytest tests/unit/scanner/test_engine.py tests/unit/scanner/test_redaction.py -v`
Expected: PASS and the raw token is absent from pytest failure representations and model dumps.

- [ ] **Step 4: Run all core tests and checks**

Run: `uv run pytest tests/unit -v`
Expected: PASS.

Run: `uv run ruff check src tests`
Expected: PASS.

Run: `uv run mypy src`
Expected: PASS.

- [ ] **Step 5: Commit the deterministic engine**

```bash
git add src/security_review/scanner tests/unit/scanner
git commit -m "feat: add deterministic security rules"
```

### Task 4: Canonical report builder and JSON/Markdown output

**Files:**
- Create: `src/security_review/reporting/__init__.py`
- Create: `src/security_review/reporting/builder.py`
- Create: `src/security_review/reporting/json_report.py`
- Create: `src/security_review/reporting/markdown.py`
- Test: `tests/unit/reporting/test_builder.py`
- Test: `tests/unit/reporting/test_formats.py`

**Interfaces:**
- Consumes: ordered `Finding` values, skipped-file warnings, and `calculate_risk`.
- Produces: `ReportFormat`, `build_report(target_name: str, findings: Sequence[Finding], warnings: Sequence[str] = ()) -> ScanReport`, `render_json(report: ScanReport) -> str`, `render_markdown(report: ScanReport) -> str`, and `render_report(report: ScanReport, format: ReportFormat) -> str`.

- [ ] **Step 1: Write failing report consistency tests**

```python
def test_report_deduplicates_and_orders_findings(finding: Finding) -> None:
    report = build_report("sample", [finding, finding])
    assert [item.id for item in report.findings] == [finding.id]
    assert report.summary.total == 1


def test_json_and_markdown_use_same_finding_id(finding: Finding) -> None:
    report = build_report("sample", [finding])
    assert finding.id in render_json(report)
    assert finding.id in render_markdown(report)
```

Also assert Markdown contains risk level, redacted evidence, remediation, and an explicit "No evidence references available" line when references are empty.

Run: `uv run pytest tests/unit/reporting -v`
Expected: FAIL because reporting modules do not exist.

- [ ] **Step 2: Implement canonical report assembly**

Deduplicate by `Finding.id`, sort with the same key as the scanner, compute risk once, use UUIDv7-compatible time-sortable IDs if the installed standard library supports them and otherwise UUID4, and set `completed_with_warnings` only when warnings are non-empty.

```python
def build_report(
    target_name: str,
    findings: Sequence[Finding],
    warnings: Sequence[str] = (),
) -> ScanReport:
    ordered = tuple(sorted({item.id: item for item in findings}.values(), key=_finding_key))
    return ScanReport(
        scan_id=str(uuid4()),
        created_at=datetime.now(UTC),
        status=ScanStatus.COMPLETED_WITH_WARNINGS if warnings else ScanStatus.COMPLETED,
        target_name=target_name,
        summary=ReportSummary.from_findings(ordered),
        risk=calculate_risk(ordered),
        findings=ordered,
        warnings=tuple(warnings),
        tool_version=__version__,
        rule_set_version="2026.09.1",
    )
```

- [ ] **Step 3: Implement stable JSON and safe Markdown renderers**

Use `model_dump_json(indent=2)` for JSON. Escape Markdown table pipes and line breaks, show relative paths only, and never render fields other than the already-redacted evidence.

Define `ReportFormat` as the string enum `json`, `markdown`, and `sarif`. `render_report` dispatches through an explicit dictionary and raises `ValueError` for any value not represented by the enum.

Run: `uv run pytest tests/unit/reporting -v`
Expected: PASS.

- [ ] **Step 4: Commit canonical reports**

```bash
git add src/security_review/reporting tests/unit/reporting src/security_review/domain
git commit -m "feat: add canonical scan reports"
```

### Task 5: SARIF 2.1.0 renderer

**Files:**
- Create: `src/security_review/reporting/sarif.py`
- Test: `tests/unit/reporting/test_sarif.py`
- Test fixture: `tests/fixtures/report.json`

**Interfaces:**
- Consumes: `ScanReport`.
- Produces: `render_sarif(report: ScanReport) -> str` containing SARIF 2.1.0 with one rule per `rule_id` and one result per finding.

- [ ] **Step 1: Write failing SARIF structure and ID tests**

```python
def test_sarif_contains_consistent_results(report: ScanReport) -> None:
    payload = json.loads(render_sarif(report))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecRAGraph"
    assert run["results"][0]["partialFingerprints"]["findingId"] == report.findings[0].id
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == report.findings[0].file_path
    )
```

Also assert critical/high map to SARIF `error`, medium maps to `warning`, low/info map to `note`, and URIs never contain drive letters or backslashes.

Run: `uv run pytest tests/unit/reporting/test_sarif.py -v`
Expected: FAIL because `render_sarif` does not exist.

- [ ] **Step 2: Implement the SARIF renderer without an extra runtime dependency**

```python
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
```

Create one `reportingDescriptor` per rule, sort rules by ID, use one-based regions, include remediation in `help`, include finding IDs in `partialFingerprints`, and serialize with `json.dumps(payload, indent=2, sort_keys=True)`.

Run: `uv run pytest tests/unit/reporting/test_sarif.py -v`
Expected: PASS.

- [ ] **Step 3: Run reporting regression tests**

Run: `uv run pytest tests/unit/reporting -v`
Expected: PASS with identical finding IDs across all renderers.

- [ ] **Step 4: Commit SARIF support**

```bash
git add src/security_review/reporting tests/unit/reporting tests/fixtures
git commit -m "feat: add SARIF security reports"
```

### Task 6: CLI and executable sample

**Files:**
- Create: `src/security_review/application.py`
- Create: `src/security_review/cli.py`
- Create: `examples/insecure/sample.py`
- Create: `examples/README.md`
- Test: `tests/e2e/test_cli.py`

**Interfaces:**
- Consumes: file discovery, rule engine, report builder, and report renderers.
- Produces: `scan_path(target: Path, limits: ScanLimits) -> ScanReport` and the `security-review scan TARGET --format json|markdown|sarif --output PATH` command.

- [ ] **Step 1: Add a controlled insecure sample with unmistakably fake data**

```python
import subprocess

DEMO_API_KEY = "demo-not-a-real-secret-12345"


def run_user_command(command: str) -> None:
    subprocess.run(command, shell=True, check=False)


def calculate(expression: str) -> object:
    return eval(expression)
```

Document that the file is a non-executed test fixture and must never contain a working credential.

- [ ] **Step 2: Write a failing CLI end-to-end test**

```python
def test_cli_writes_json_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        ["scan", "examples/insecure", "--format", "json", "--output", str(output)],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] >= 3
    assert "demo-not-a-real-secret-12345" not in output.read_text(encoding="utf-8")
```

Also test an unsupported target exits with code 2 and a no-findings target exits successfully.

Add a clock-controlled test that advances beyond `ScanLimits.max_processing_seconds` between two files and asserts the scan stops with the stable warning code `processing_time_limit_exceeded` instead of continuing indefinitely.

Run: `uv run pytest tests/e2e/test_cli.py -v`
Expected: FAIL because the CLI is not implemented.

- [ ] **Step 3: Implement the shared application service and Typer command**

```python
@app.command()
def scan(
    target: Annotated[Path, typer.Argument(exists=True, readable=True)],
    format: Annotated[ReportFormat, typer.Option("--format")] = ReportFormat.MARKDOWN,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    report = scan_path(target, ScanLimits())
    rendered = render_report(report, format)
    if output is None:
        typer.echo(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
```

Keep orchestration in `scan_path`; the CLI only parses arguments and handles output. Compute one monotonic deadline at scan start and check it before reading each file and applying each rule batch. Convert deadline exhaustion to the stable warning code `processing_time_limit_exceeded`. Do not catch unexpected exceptions without converting them to a stable nonzero exit.

Run: `uv run pytest tests/e2e/test_cli.py -v`
Expected: PASS.

- [ ] **Step 4: Verify the installed command manually**

Run: `uv run security-review scan examples/insecure --format markdown`
Expected: a redacted report with at least `SEC001`, `PY001`, and `PY002`, with no raw demo token.

Run: `uv run security-review scan examples/insecure --format sarif --output build/sample.sarif`
Expected: valid JSON with SARIF version `2.1.0`.

- [ ] **Step 5: Run the complete core gate**

Run: `uv run pytest --cov=security_review --cov-report=term-missing`
Expected: PASS.

Run: `uv run ruff check src tests examples`
Expected: PASS.

Run: `uv run mypy src`
Expected: PASS.

- [ ] **Step 6: Commit the working core scanner**

```bash
git add src/security_review/application.py src/security_review/cli.py examples tests/e2e pyproject.toml uv.lock
git commit -m "feat: ship local security review CLI"
```
