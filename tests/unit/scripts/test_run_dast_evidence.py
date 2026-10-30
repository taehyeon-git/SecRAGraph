"""The DAST evidence gate scans only its disposable fixture and cleans up."""

from __future__ import annotations

import subprocess
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from scripts import run_dast_evidence

ROOT = Path(__file__).resolve().parents[3]
ACTIVE_PATHS = (
    "/sql-vulnerable",
    "/sql-safe",
    "/sql-numeric-vulnerable",
    "/sql-numeric-safe",
    "/redirect-vulnerable",
    "/redirect-safe",
)
PASSIVE_PATHS = ("/public", "/protected", *ACTIVE_PATHS)
BENCHMARK_SHA = "32ecbfb19e6eabd27d9988d71fdb60058740fa44f4d3cb69cdc1c2c0a0d2fdff"


def test_reviewed_manifest_digest_matches_file() -> None:
    assert (
        sha256((ROOT / "data/evaluation/dast_cases.json").read_bytes()).hexdigest() == BENCHMARK_SHA
    )
    assert run_dast_evidence._BENCHMARK_SHA == BENCHMARK_SHA


def _benchmark_result(*, sqli_tp: int = 1, sqli_fp: int = 0) -> Any:
    header = SimpleNamespace(tp=1, fp=0, fn=0, tn=1)
    redirect = SimpleNamespace(tp=1, fp=0, fn=0, tn=1)
    sqli = SimpleNamespace(tp=sqli_tp, fp=sqli_fp, fn=2 - sqli_tp, tn=2 - sqli_fp)
    return SimpleNamespace(
        manifest_sha256=BENCHMARK_SHA,
        metrics=SimpleNamespace(tp=2 + sqli_tp, fp=sqli_fp, fn=2 - sqli_tp, tn=4 - sqli_fp),
        rules=(("ZAP/10021", header), ("ZAP/20019", redirect), ("ZAP/40018", sqli)),
    )


def _manifest() -> Any:
    cases = tuple(
        SimpleNamespace(
            mode="active" if path in ACTIVE_PATHS else "passive",
            method="GET",
            path=path,
        )
        for path in PASSIVE_PATHS
    )
    return SimpleNamespace(cases=cases, sha256=BENCHMARK_SHA)


def _report(*, completed: bool = True, finding: bool = True, active: bool = False) -> Any:
    findings = (
        (
            SimpleNamespace(
                engine="zap",
                rule_id="ZAP/40018" if active else "ZAP/10021",
                http_method="GET",
                http_path="/sql-vulnerable" if active else "/public",
                file_path=None,
                cwe_ids=("CWE-89",) if active else (),
            ),
        )
        if finding
        else ()
    )
    execution = SimpleNamespace(
        engine="zap",
        kind="dast",
        status="completed" if completed else "error",
        checks=("openapi-active",) if active else ("openapi-passive",),
        eligible_endpoints=tuple(f"GET {path}" for path in ACTIVE_PATHS)
        if active
        else tuple(f"GET {path}" for path in PASSIVE_PATHS),
    )
    return SimpleNamespace(findings=findings, executions=(execution,))


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: Any | None = None,
    active_report: Any | None = None,
    authenticated_requests: int = 1,
    public_requests: int = 1,
) -> tuple[list[tuple[str, tuple[str, ...]]], list[Any]]:
    calls: list[tuple[str, tuple[str, ...]]] = []
    scans: list[Any] = []
    stats_calls = 0

    def compose(project: str, args: list[str], _environment: dict[str, str], _timeout: int):
        calls.append((project, tuple(args)))
        return subprocess.CompletedProcess(args, 0, "", "")

    def scan(
        container: str, port: int, openapi_path: str, *, auth_header_env: str, active: bool = False
    ):
        scans.append((container, port, openapi_path, auth_header_env, active))
        if active:
            return active_report if active_report is not None else _report(active=True)
        return report if report is not None else _report()

    monkeypatch.setattr(run_dast_evidence, "_run_compose", compose)
    monkeypatch.setattr(run_dast_evidence, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(run_dast_evidence, "_prepare_zap_image", lambda: None)
    monkeypatch.setattr(run_dast_evidence, "_fixture_container", lambda *_args: "a" * 64)
    monkeypatch.setattr(
        run_dast_evidence, "_fixture_image_id", lambda _container: "sha256:" + "b" * 64
    )
    monkeypatch.setattr(run_dast_evidence, "_source_identity", lambda: ("c" * 40, True))
    monkeypatch.setattr(run_dast_evidence, "load_manifest", lambda _path: _manifest())

    result = _benchmark_result()
    monkeypatch.setattr(
        run_dast_evidence, "evaluate_dast_benchmark", lambda *_args, **_kwargs: result
    )
    monkeypatch.setattr(
        run_dast_evidence, "render_benchmark_json", lambda _result: '{"metrics":{}}'
    )
    monkeypatch.setattr(run_dast_evidence, "render_benchmark_markdown", lambda _result: "benchmark")

    def fixture_json(_container: str, path: str) -> dict[str, object]:
        nonlocal stats_calls
        if path == "/health":
            return {"status": "ok"}
        stats_calls += 1
        if stats_calls == 1:
            phase = 0
        elif stats_calls == 2:
            phase = 1
        else:
            phase = 2
        return {
            "authenticated_protected_requests": authenticated_requests if phase > 0 else 0,
            "public_requests": public_requests if phase > 0 else 0,
            "route_requests": {path: phase for path in PASSIVE_PATHS},
            "attack_probes": {path: int(phase == 2) for path in ACTIVE_PATHS},
        }

    monkeypatch.setattr(run_dast_evidence, "_fetch_fixture_json", fixture_json)
    monkeypatch.setattr(run_dast_evidence, "_scan", scan)
    monkeypatch.setattr(
        run_dast_evidence, "_assert_host_redirect_isolated", lambda _container: None
    )
    monkeypatch.setattr(run_dast_evidence, "render_report", lambda _report, fmt: fmt.value)
    monkeypatch.setattr(run_dast_evidence.secrets, "token_urlsafe", lambda _length: "test-token")
    return calls, scans


def test_two_scans_render_separate_formats_and_clean_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, scans = _install_fakes(monkeypatch)

    run_dast_evidence.run_evidence(tmp_path)

    assert scans == [
        ("a" * 64, 8000, "/openapi.json", "ZAP_AUTH_HEADER_VALUE", False),
        ("a" * 64, 8000, "/openapi.json", "ZAP_AUTH_HEADER_VALUE", True),
    ]
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert calls[0][0] == calls[1][0]
    assert calls[0][0].startswith("secragraph-dast-")
    assert "--volumes" in calls[1][1]
    assert (tmp_path / "dast.json").read_text(encoding="utf-8") == "json"
    assert (tmp_path / "dast.md").read_text(encoding="utf-8") == "markdown"
    assert (tmp_path / "dast.sarif").read_text(encoding="utf-8") == "sarif"
    for suffix in ("json", "md", "sarif"):
        assert (tmp_path / f"dast-active.{suffix}").exists()
    assert (tmp_path / "dast-benchmark.json").exists()
    assert (tmp_path / "dast-benchmark.md").exists()


def test_fixture_start_failure_still_tears_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)

    def failing_compose(project: str, args: list[str], environment: dict[str, str], timeout: int):
        calls.append((project, tuple(args)))
        return subprocess.CompletedProcess(args, 1 if args[0] == "up" else 0, "", "")

    monkeypatch.setattr(run_dast_evidence, "_run_compose", failing_compose)

    with pytest.raises(RuntimeError, match="fixture_start_failed"):
        run_dast_evidence.run_evidence(tmp_path)

    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast.*"))


def test_fixture_cleanup_failure_leaves_no_new_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)
    (tmp_path / "dast.json").write_text("stale", encoding="utf-8")
    (tmp_path / "dast-active.json").write_text("stale", encoding="utf-8")
    (tmp_path / "dast-benchmark.json").write_text("stale", encoding="utf-8")

    def failing_down(project: str, args: list[str], environment: dict[str, str], timeout: int):
        calls.append((project, tuple(args)))
        return subprocess.CompletedProcess(args, 1 if args[0] == "down" else 0, "", "")

    monkeypatch.setattr(run_dast_evidence, "_run_compose", failing_down)
    with pytest.raises(RuntimeError, match="fixture_cleanup_failed"):
        run_dast_evidence.run_evidence(tmp_path)
    assert not list(tmp_path.glob("dast*"))


@pytest.mark.parametrize(
    ("report", "authenticated_requests", "reason"),
    [
        (_report(completed=False), 1, "dast_incomplete"),
        (_report(), 0, "authenticated_route_not_tested"),
    ],
)
def test_incomplete_evidence_fails_and_cleans(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    report: Any,
    authenticated_requests: int,
    reason: str,
) -> None:
    calls, _ = _install_fakes(
        monkeypatch, report=report, authenticated_requests=authenticated_requests
    )

    with pytest.raises(RuntimeError, match=reason):
        run_dast_evidence.run_evidence(tmp_path)

    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast.*"))


def test_token_in_renderer_output_is_rejected_without_writing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)
    monkeypatch.setattr(run_dast_evidence, "render_report", lambda _report, _fmt: "test-token")

    with pytest.raises(RuntimeError, match="credential_in_report"):
        run_dast_evidence.run_evidence(tmp_path)

    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast.*"))


def test_token_in_benchmark_output_is_rejected_after_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)
    monkeypatch.setattr(
        run_dast_evidence, "render_benchmark_markdown", lambda _result: "Session test-token"
    )
    with pytest.raises(RuntimeError, match="credential_in_report"):
        run_dast_evidence.run_evidence(tmp_path)
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast*"))


def test_host_redirect_escape_fails_evidence_and_still_cleans_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)

    def escaped(_container: str) -> None:
        raise RuntimeError("host_redirect_escaped")

    monkeypatch.setattr(run_dast_evidence, "_assert_host_redirect_isolated", escaped)
    with pytest.raises(RuntimeError, match="host_redirect_escaped"):
        run_dast_evidence.run_evidence(tmp_path)

    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast.*"))


def test_missing_alert_is_scored_instead_of_aborting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fakes(
        monkeypatch,
        report=_report(finding=False),
        active_report=_report(active=True, finding=False),
    )
    run_dast_evidence.run_evidence(tmp_path)
    assert (tmp_path / "dast-benchmark.json").exists()


def test_active_execution_requires_exact_manifest_seeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _report(active=True)
    report.executions[0].eligible_endpoints = ("GET /sql-vulnerable", "GET /sql-safe")
    _install_fakes(monkeypatch, active_report=report)
    with pytest.raises(RuntimeError, match="active_execution_missing"):
        run_dast_evidence.run_evidence(tmp_path)
    assert not list(tmp_path.glob("dast*"))


def test_benchmark_refusal_leaves_no_artifacts_after_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise ValueError("incomplete_proof")

    monkeypatch.setattr(run_dast_evidence, "evaluate_dast_benchmark", refuse)
    with pytest.raises(ValueError, match="incomplete_proof"):
        run_dast_evidence.run_evidence(tmp_path)
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast*"))


@pytest.mark.parametrize("result", [_benchmark_result(sqli_tp=0), _benchmark_result(sqli_fp=1)])
def test_benchmark_regression_fails_after_cleanup_without_publishing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: Any
) -> None:
    calls, _ = _install_fakes(monkeypatch)
    monkeypatch.setattr(
        run_dast_evidence, "evaluate_dast_benchmark", lambda *_args, **_kwargs: result
    )
    with pytest.raises(RuntimeError, match="benchmark_regression"):
        run_dast_evidence.run_evidence(tmp_path)
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert not list(tmp_path.glob("dast*"))


def test_benchmark_manifest_change_requires_new_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fakes(monkeypatch)
    altered = _manifest()
    altered.sha256 = "b" * 64
    monkeypatch.setattr(run_dast_evidence, "load_manifest", lambda _path: altered)
    with pytest.raises(RuntimeError, match="benchmark_manifest_unreviewed"):
        run_dast_evidence.run_evidence(tmp_path)
    assert not list(tmp_path.glob("dast*"))


def test_stats_phases_and_identity_reach_benchmark(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, _ = _install_fakes(monkeypatch)
    captured: list[tuple[tuple[object, ...], dict[str, object]]] = []
    result = _benchmark_result()

    def evaluate(*args: object, **kwargs: object) -> Any:
        assert calls[-1][1][0] == "down"
        captured.append((args, kwargs))
        return result

    monkeypatch.setattr(run_dast_evidence, "evaluate_dast_benchmark", evaluate)
    run_dast_evidence.run_evidence(tmp_path)
    args, kwargs = captured[0]
    assert args[3]["route_requests"]["/public"] == 0
    assert args[4]["route_requests"]["/public"] == 1
    assert args[5]["attack_probes"]["/sql-vulnerable"] == 1
    assert kwargs["fixture_image_id"] == "sha256:" + "b" * 64
    assert kwargs["source_revision"] == "c" * 40
    assert kwargs["source_dirty"] is True
    assert isinstance(kwargs["total_elapsed_ms"], int)


def test_fixture_image_identity_rejects_unexpected_inspect_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_dast_evidence,
        "_run_docker",
        lambda _args: subprocess.CompletedProcess(["docker"], 0, "not-an-image", ""),
    )
    with pytest.raises(RuntimeError, match="fixture_image_unavailable"):
        run_dast_evidence._fixture_image_id("a" * 64)


def test_probe_docker_cleanup_timeout_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(_args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(["docker"], timeout)

    monkeypatch.setattr(run_dast_evidence, "_run_docker", timeout)
    assert not run_dast_evidence._cleanup_docker(["network", "rm", "temporary"])


def test_prepare_zap_image_uses_bounded_runner_pull(monkeypatch: pytest.MonkeyPatch) -> None:
    deadlines: list[float] = []

    def ready(deadline: float) -> bool:
        deadlines.append(deadline)
        return True

    monkeypatch.setattr(run_dast_evidence, "prepare_zap_image", ready)
    run_dast_evidence._prepare_zap_image()
    assert len(deadlines) == 1
    assert deadlines[0] > run_dast_evidence.monotonic()


def test_prepare_zap_image_fails_closed_on_pull_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_dast_evidence, "prepare_zap_image", lambda _deadline: False)
    with pytest.raises(RuntimeError, match="zap_image_unavailable"):
        run_dast_evidence._prepare_zap_image()


def test_incomplete_report_surfaces_only_known_runner_reason() -> None:
    report = _report(completed=False)
    report.executions[0].reason = "dast_zap_image_unavailable"
    with pytest.raises(RuntimeError, match="dast_zap_image_unavailable"):
        run_dast_evidence._require_evidence(report, allowed_paths=frozenset(PASSIVE_PATHS))
    report.executions[0].reason = "Session secret-value"
    with pytest.raises(RuntimeError, match="dast_incomplete"):
        run_dast_evidence._require_evidence(report, allowed_paths=frozenset(PASSIVE_PATHS))


def test_missing_active_completion_marker_surfaces_safe_reason() -> None:
    report = _report(active=True, completed=False)
    report.executions[0].reason = "dast_active_scan_incomplete"
    with pytest.raises(RuntimeError, match="dast_active_scan_incomplete"):
        run_dast_evidence._require_active_evidence(
            report,
            expected_endpoints=frozenset(f"GET {path}" for path in ACTIVE_PATHS),
            allowed_paths=frozenset(ACTIVE_PATHS),
        )


def test_scope_rejects_finding_outside_manifest() -> None:
    report = _report()
    report.findings[0].http_path = "/health"
    with pytest.raises(RuntimeError, match="dast_scope_violation"):
        run_dast_evidence._require_evidence(report, allowed_paths=frozenset(PASSIVE_PATHS))


def test_main_prints_only_allowlisted_failure_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> None:
        raise RuntimeError("zap_image_unavailable")

    monkeypatch.setattr(run_dast_evidence, "run_evidence", fail)
    assert run_dast_evidence.main() == 1
    assert "(zap_image_unavailable)" in capsys.readouterr().err


def test_main_prints_generic_failure_without_exception_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> None:
        raise RuntimeError("secret test-token must not appear")

    monkeypatch.setattr(run_dast_evidence, "run_evidence", fail)

    assert run_dast_evidence.main() == 1
    output = capsys.readouterr()
    assert "test-token" not in output.out + output.err
    assert "DAST evidence" in output.err
    assert "unknown:RuntimeError" in output.err


def test_unknown_failure_location_uses_only_fixed_file_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def permission_denied() -> str:
        raise PermissionError("Session secret-must-not-log")

    monkeypatch.setattr(run_dast_evidence, "_docker_executable", permission_denied)
    with pytest.raises(PermissionError) as caught:
        run_dast_evidence._run_docker(["version"])
    location = run_dast_evidence._safe_failure_location(caught.value)
    assert "run_dast_evidence.py:" in location
    assert "secret-must-not-log" not in location


def test_evidence_prints_only_safe_stage_names(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _install_fakes(monkeypatch)
    run_dast_evidence.run_evidence(tmp_path)
    output = capsys.readouterr().out
    for stage in (
        "image-ready",
        "fixture-ready",
        "passive-returned",
        "active-returned",
        "evidence-checked",
        "cleanup-complete",
    ):
        assert f"DAST stage: {stage}" in output


def test_ci_has_separate_dast_gate_and_only_normalized_artifacts() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["dast-evidence"]
    steps = job["steps"]
    assert any("scripts.run_dast_evidence" in step.get("run", "") for step in steps)
    upload = next(step for step in steps if "actions/upload-artifact@" in step.get("uses", ""))
    condition = upload["if"]
    assert "github.ref == 'refs/heads/main'" in condition
    assert all(
        f"github.event_name == '{event}'" in condition
        for event in ("push", "schedule", "workflow_dispatch")
    )
    assert set(upload["with"]["path"].splitlines()) == {
        "build/evidence/dast.json",
        "build/evidence/dast.md",
        "build/evidence/dast.sarif",
        "build/evidence/dast-active.json",
        "build/evidence/dast-active.md",
        "build/evidence/dast-active.sarif",
        "build/evidence/dast-benchmark.json",
        "build/evidence/dast-benchmark.md",
    }
    assert upload["with"]["if-no-files-found"] == "error"
