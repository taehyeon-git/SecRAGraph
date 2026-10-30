from __future__ import annotations

import json
import shutil
import subprocess
from io import BytesIO
from uuid import uuid4
from zipfile import ZipFile

import pytest

from scripts import compose_smoke


def test_expected_findings_require_matching_rule_and_fixture_file() -> None:
    findings = [
        {
            "id": "1",
            "engine": "opengrep",
            "rule_id": "OG/python_eval_rule-eval",
            "file_path": "app.py",
            "line_start": 1,
        },
        {
            "id": "2",
            "engine": "gitleaks",
            "rule_id": "GITLEAKS/generic-api-key",
            "file_path": "secret.env",
            "line_start": 1,
        },
        {
            "id": "3",
            "engine": "checkov",
            "rule_id": "CHECKOV/CKV_AWS_18",
            "file_path": "bucket.tf",
            "line_start": 1,
        },
        {
            "id": "4",
            "engine": "compose-policy",
            "rule_id": "COMPOSE/PRIVILEGED",
            "file_path": "compose.yaml",
            "line_start": 4,
        },
    ]
    compose_smoke._validate_expected_findings(findings)

    for engine, field, wrong in (
        ("opengrep", "rule_id", "OG/other"),
        ("gitleaks", "file_path", "app.py"),
        ("checkov", "rule_id", "OTHER/CKV_AWS_18"),
        ("compose-policy", "file_path", "bucket.tf"),
    ):
        corrupted = [dict(item) for item in findings]
        next(item for item in corrupted if item["engine"] == engine)[field] = wrong
        with pytest.raises(ValueError, match="synthetic_finding_missing"):
            compose_smoke._validate_expected_findings(corrupted)


def test_sarif_results_must_match_persisted_finding_identity_and_location() -> None:
    findings = [
        {
            "id": "1",
            "engine": "opengrep",
            "rule_id": "OG/python_eval_rule-eval",
            "file_path": "app.py",
            "line_start": 1,
        }
    ]
    result = {
        "ruleId": "OG/python_eval_rule-eval",
        "properties": {"findingId": "1", "engine": "opengrep"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "SecRAGraph", "rules": [{"id": "OG/python_eval_rule-eval"}]}
                },
                "results": [result],
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }
    compose_smoke._validate_sarif(sarif, findings)

    for change in (
        {"ruleId": "OG/other"},
        {"properties": {"findingId": "wrong", "engine": "opengrep"}},
        {"locations": []},
    ):
        corrupted = dict(result) | change
        sarif["runs"][0]["results"] = [corrupted]
        with pytest.raises(ValueError, match="sarif_report_invalid"):
            compose_smoke._validate_sarif(sarif, findings)


def test_markdown_must_display_the_same_finding_count_and_sections() -> None:
    findings = [
        {"id": "1", "rule_id": "R1", "engine": "opengrep", "file_path": "app.py", "line_start": 1},
        {
            "id": "2",
            "rule_id": "R2",
            "engine": "gitleaks",
            "file_path": "secret.env",
            "line_start": 2,
        },
    ]
    valid = (
        "# SecRAGraph Security Review\n"
        "- Scan ID: scan-1\n"
        "- Findings: 2\n"
        "## Scan coverage\n### opengrep (sast)\n"
        "## Findings\n"
        "### 1\n- Rule: R1\n- Engine: opengrep\n- Location: app.py:1\n"
        "### 2\n- Rule: R2\n- Engine: gitleaks\n- Location: secret.env:2\n"
    )
    compose_smoke._validate_markdown(valid, "scan-1", findings)

    for invalid in (
        valid.replace("- Findings: 2", "- Findings: 1"),
        valid.replace("### 2", "### wrong"),
        valid.replace("- Rule: R2", "- Rule: wrong"),
        valid.replace("- Location: secret.env:2", "- Location: app.py:2"),
    ):
        with pytest.raises(ValueError, match="markdown_report_invalid"):
            compose_smoke._validate_markdown(invalid, "scan-1", findings)


def test_benchmark_archive_covers_four_engines_without_external_dependency() -> None:
    archive = compose_smoke._mixed_archive()
    with ZipFile(BytesIO(archive)) as package:
        names = set(package.namelist())
        assert {"app.py", "secret.env", "compose.yaml", "bucket.tf"} == names
        assert b"eval(input())" in package.read("app.py")
        assert b"privileged: true" in package.read("compose.yaml")
        assert b"MY_API_KEY=" in package.read("secret.env")


def test_source_provenance_marks_untracked_source_dirty(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is required for source provenance")
    subprocess.run([git, "init", str(tmp_path)], check=True, capture_output=True)  # noqa: S603
    (tmp_path / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "tracked.txt"], check=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        [
            git,
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Benchmark",
            "-c",
            "user.email=benchmark@example.invalid",
            "commit",
            "-m",
            "baseline",
        ],
        check=True,
        capture_output=True,
    )
    (tmp_path / "new_source.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(compose_smoke, "_ROOT", tmp_path)

    revision, dirty = compose_smoke._source_provenance()

    assert len(revision) == 40
    assert dirty is True


def test_benchmark_endpoints_measure_auth_owned_reports_and_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = str(uuid4())
    executions = [
        {
            "engine": engine,
            "kind": kind,
            "status": "completed",
            "elapsed_ms": 5,
            "eligible_files": [file_name],
            "scanned_files": [file_name],
            "checks": [f"{engine}/fixture"],
        }
        for engine, kind, file_name in (
            ("opengrep", "sast", "app.py"),
            ("gitleaks", "secret", "secret.env"),
            ("checkov", "configuration", "bucket.tf"),
            ("compose-policy", "configuration", "compose.yaml"),
        )
    ]
    payload: dict[str, object] = {
        "scan_id": scan_id,
        "status": "completed",
        "summary": {"total": 4},
        "findings": [
            {
                "id": "1",
                "engine": "opengrep",
                "rule_id": "OG/python_eval_rule-eval",
                "file_path": "app.py",
                "line_start": 1,
            },
            {
                "id": "2",
                "engine": "gitleaks",
                "rule_id": "GITLEAKS/generic-api-key",
                "file_path": "secret.env",
                "line_start": 1,
            },
            {
                "id": "3",
                "engine": "checkov",
                "rule_id": "CHECKOV/CKV_AWS_18",
                "file_path": "bucket.tf",
                "line_start": 1,
            },
            {
                "id": "4",
                "engine": "compose-policy",
                "rule_id": "COMPOSE/PRIVILEGED",
                "file_path": "compose.yaml",
                "line_start": 4,
            },
        ],
        "warnings": [],
        "executions": executions,
    }
    calls: list[tuple[str, str, str | None]] = []

    class Response:
        def __init__(self, status_code: int, body: object = None):
            self.status_code = status_code
            self.text = body if isinstance(body, str) else json.dumps(body or {})
            self._body = body

        def json(self):
            return json.loads(self._body) if isinstance(self._body, str) else self._body

    class Client:
        def __init__(self, **_kwargs: object):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args: object):
            pass

        def post(self, url: str, **kwargs: object):
            calls.append(("POST", url, None))
            if url.endswith("/v1/auth/login"):
                username = kwargs["json"]["username"]
                return Response(200, {"token": f"session-{username}"})
            assert url.endswith("/v1/scans/archive")
            if "headers" not in kwargs:
                return Response(401)
            assert kwargs["timeout"] == 120
            name, content, media_type = kwargs["files"]["file"]
            assert name == "benchmark.zip" and media_type == "application/zip"
            with ZipFile(BytesIO(content)) as package:
                assert "app.py" in package.namelist()
            return Response(200, payload)

        def get(self, url: str, **kwargs: object):
            calls.append(("GET", url, kwargs.get("headers", {}).get("Authorization")))
            if url.endswith("/health/ready") or url.endswith("/_stcore/health"):
                return Response(200, {"status": "ok"})
            authorization = kwargs.get("headers", {}).get("Authorization")
            if authorization is None:
                return Response(401)
            if authorization == "Session session-other":
                return Response(404)
            if url.endswith("format=markdown"):
                rendered_findings = "".join(
                    f"### {finding['id']}\n"
                    f"- Rule: {compose_smoke._markdown_escape(finding['rule_id'])}\n"
                    f"- Engine: {finding['engine']}\n"
                    f"- Location: {finding['file_path']}:{finding['line_start']}\n"
                    for finding in payload["findings"]
                )
                return Response(
                    200,
                    f"# SecRAGraph Security Review\n- Scan ID: {scan_id}\n"
                    "- Findings: 4\n## Scan coverage\n## Findings\n" + rendered_findings,
                )
            if url.endswith("format=sarif"):
                findings = payload["findings"]
                return Response(
                    200,
                    json.dumps(
                        {
                            "version": "2.1.0",
                            "runs": [
                                {
                                    "tool": {
                                        "driver": {
                                            "name": "SecRAGraph",
                                            "rules": [
                                                {"id": finding["rule_id"]} for finding in findings
                                            ],
                                        }
                                    },
                                    "invocations": [{"executionSuccessful": True}],
                                    "results": [
                                        {
                                            "ruleId": finding["rule_id"],
                                            "properties": {
                                                "findingId": finding["id"],
                                                "engine": finding["engine"],
                                            },
                                            "locations": [
                                                {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": finding["file_path"]
                                                        },
                                                        "region": {
                                                            "startLine": finding["line_start"]
                                                        },
                                                    }
                                                }
                                            ],
                                        }
                                        for finding in findings
                                    ],
                                }
                            ],
                        }
                    ),
                )
            return Response(200, payload)

    monkeypatch.setattr(compose_smoke.httpx, "Client", Client)
    result = compose_smoke._smoke_endpoints(41001, 41002, "member", "password", "other", "password")

    assert set(result["stages_ms"]) == {
        "api_ready",
        "web_ready",
        "login",
        "upload",
        "persisted_json",
        "markdown",
        "sarif",
    }
    assert all(result["checks"].values())
    assert {item["engine"] for item in result["executions"]} == {
        "opengrep",
        "gitleaks",
        "checkov",
        "compose-policy",
    }
    marker = "S3cr3t-" + "X9a2Q7b5R8c1"
    assert marker not in json.dumps(result)
    assert ("POST", "http://127.0.0.1:41001/v1/scans/archive", None) in calls
    assert (
        sum(method == "POST" and url.endswith("/v1/scans/archive") for method, url, _ in calls) == 2
    )
    assert sum(auth == "Session session-other" for method, _, auth in calls if method == "GET") == 3


def test_failed_compose_start_still_cleans_exact_isolated_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []
    ports = iter((41001, 41002, 41003, 41004))
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker", raising=False)
    monkeypatch.setattr(compose_smoke, "_reserve_port", lambda: next(ports), raising=False)

    def fake_compose(
        _docker: str,
        project: str,
        arguments: list[str],
        _environment: dict[str, str],
        _timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((project, tuple(arguments)))
        return subprocess.CompletedProcess(arguments, 1 if arguments[0] == "up" else 0)

    monkeypatch.setattr(compose_smoke, "_run_compose", fake_compose)

    assert compose_smoke.main() == 1
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert calls[0][0] == calls[1][0]
    assert calls[0][0].startswith("secragraph-smoke-")
    assert "--volumes" in calls[1][1]


def test_smoke_provisions_member_and_does_not_configure_operator_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(compose_smoke, "_ROOT", tmp_path)
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    environments: list[dict[str, str]] = []
    members: list[str] = []

    def fake_compose(_docker, _project, arguments, environment, _timeout):
        environments.append(environment.copy())
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(compose_smoke, "_run_compose", fake_compose)
    monkeypatch.setattr(
        compose_smoke,
        "_smoke_endpoints",
        lambda *_args: {
            "fixture_sha256": "a" * 64,
            "stages_ms": {
                "api_ready": 1,
                "web_ready": 1,
                "login": 1,
                "upload": 5,
                "persisted_json": 1,
                "markdown": 1,
                "sarif": 1,
            },
            "checks": {"member_login": True, "engine_coverage": True},
            "executions": [],
            "report": {"scan_status": "completed", "finding_count": 4, "warnings_count": 0},
        },
    )
    monkeypatch.setattr(
        compose_smoke,
        "_create_synthetic_member",
        lambda _docker, _project, _env, username, _password: members.append(username),
    )
    monkeypatch.setattr(
        compose_smoke, "_source_provenance", lambda: ("a" * 40, False), raising=False
    )

    assert compose_smoke.main() == 0
    assert all("SECRAGRAPH_API_TOKEN" not in env for env in environments)
    assert all(env["SECRAGRAPH_AUTO_OSV_ENABLED"] == "false" for env in environments)
    assert all(env["SECRAGRAPH_AUTO_CWE_ENABLED"] == "false" for env in environments)
    assert len(members) == 2 and members[0] != members[1]
    result = json.loads((tmp_path / "build/evidence/pipeline-api.json").read_text(encoding="utf-8"))
    assert result["source_revision"] == "a" * 40
    assert result["source_dirty"] is False
    assert result["status"] == "completed"
    assert result["stages_ms"]["startup"] >= 0
    assert result["stages_ms"]["cleanup"] >= 0
    assert result["limitations"]
    markdown = (tmp_path / "build/evidence/pipeline-api.md").read_text(encoding="utf-8")
    assert "OSV" in markdown and "RAG" in markdown
    assert "password" not in markdown


def test_smoke_reports_safe_failure_code_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    monkeypatch.setattr(
        compose_smoke,
        "_run_compose",
        lambda _docker, _project, arguments, _env, _timeout: subprocess.CompletedProcess(
            arguments, 0
        ),
    )
    monkeypatch.setattr(compose_smoke, "_create_synthetic_member", lambda *_args: None)

    def fail_endpoints(*_args: object) -> None:
        raise ValueError("synthetic_finding_missing")

    monkeypatch.setattr(compose_smoke, "_smoke_endpoints", fail_endpoints)
    assert compose_smoke.main() == 1
    assert "synthetic_finding_missing" in capsys.readouterr().err


def test_smoke_suppresses_untrusted_exception_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(compose_smoke, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(compose_smoke, "_reserve_port", iter((41001, 41002, 41003, 41004)).__next__)
    monkeypatch.setattr(
        compose_smoke,
        "_run_compose",
        lambda _docker, _project, arguments, _env, _timeout: subprocess.CompletedProcess(
            arguments, 0
        ),
    )

    def fail_member(*_args: object) -> None:
        raise ValueError("synthetic secret marker")

    monkeypatch.setattr(compose_smoke, "_create_synthetic_member", fail_member)
    assert compose_smoke.main() == 1
    output = capsys.readouterr().err
    assert "member_exception" in output
    assert "synthetic secret marker" not in output
