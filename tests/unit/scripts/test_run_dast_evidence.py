"""The DAST evidence gate scans only its disposable fixture and cleans up."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from scripts import run_dast_evidence

ROOT = Path(__file__).resolve().parents[3]


def _report(*, completed: bool = True, finding: bool = True) -> Any:
    findings = (
        (
            SimpleNamespace(
                engine="zap",
                rule_id="ZAP/10021",
                http_method="GET",
                http_path="/public",
                file_path=None,
            ),
        )
        if finding
        else ()
    )
    execution = SimpleNamespace(
        engine="zap", kind="dast", status="completed" if completed else "error"
    )
    return SimpleNamespace(findings=findings, executions=(execution,))


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: Any | None = None,
    authenticated_requests: int = 1,
    public_requests: int = 1,
) -> tuple[list[tuple[str, tuple[str, ...]]], list[Any]]:
    calls: list[tuple[str, tuple[str, ...]]] = []
    scans: list[Any] = []

    def compose(project: str, args: list[str], _environment: dict[str, str], _timeout: int):
        calls.append((project, tuple(args)))
        return subprocess.CompletedProcess(args, 0, "", "")

    def scan(container: str, port: int, openapi_path: str, *, auth_header_env: str):
        scans.append((container, port, openapi_path, auth_header_env))
        return report if report is not None else _report()

    monkeypatch.setattr(run_dast_evidence, "_run_compose", compose)
    monkeypatch.setattr(run_dast_evidence, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(run_dast_evidence, "_prepare_zap_image", lambda: None)
    monkeypatch.setattr(run_dast_evidence, "_fixture_container", lambda *_args: "a" * 64)
    monkeypatch.setattr(
        run_dast_evidence,
        "_fetch_fixture_json",
        lambda _container, path: (
            {"status": "ok"}
            if path == "/health"
            else {
                "authenticated_protected_requests": authenticated_requests,
                "public_requests": public_requests,
            }
        ),
    )
    monkeypatch.setattr(run_dast_evidence, "_scan", scan)
    monkeypatch.setattr(
        run_dast_evidence, "_assert_host_redirect_isolated", lambda _container: None
    )
    monkeypatch.setattr(run_dast_evidence, "render_report", lambda _report, fmt: fmt.value)
    monkeypatch.setattr(run_dast_evidence.secrets, "token_urlsafe", lambda _length: "test-token")
    return calls, scans


def test_one_scan_renders_three_formats_and_cleans_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls, scans = _install_fakes(monkeypatch)

    run_dast_evidence.run_evidence(tmp_path)

    assert len(scans) == 1
    assert scans[0] == ("a" * 64, 8000, "/openapi.json", "ZAP_AUTH_HEADER_VALUE")
    assert [args[0] for _, args in calls] == ["up", "down"]
    assert calls[0][0] == calls[1][0]
    assert calls[0][0].startswith("secragraph-dast-")
    assert "--volumes" in calls[1][1]
    assert (tmp_path / "dast.json").read_text(encoding="utf-8") == "json"
    assert (tmp_path / "dast.md").read_text(encoding="utf-8") == "markdown"
    assert (tmp_path / "dast.sarif").read_text(encoding="utf-8") == "sarif"


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


@pytest.mark.parametrize(
    ("report", "authenticated_requests", "reason"),
    [
        (_report(completed=False), 1, "dast_incomplete"),
        (_report(finding=False), 1, "expected_alert_missing"),
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
        run_dast_evidence._require_evidence(report)
    report.executions[0].reason = "Session secret-value"
    with pytest.raises(RuntimeError, match="dast_incomplete"):
        run_dast_evidence._require_evidence(report)


def test_public_route_must_be_requested_before_expected_alert_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fakes(monkeypatch, report=_report(finding=False), public_requests=0)
    with pytest.raises(RuntimeError, match="public_route_not_tested"):
        run_dast_evidence.run_evidence(tmp_path)


def test_missing_alert_logs_only_bounded_rule_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _report(finding=False)
    report.executions[0].eligible_endpoints = ("GET /public",)
    report.findings = (
        SimpleNamespace(
            engine="zap",
            rule_id="ZAP/10020",
            http_method="GET",
            http_path="/public",
            file_path=None,
        ),
        SimpleNamespace(
            engine="zap",
            rule_id="Session secret-must-not-log",
            http_method="GET",
            http_path="/public",
            file_path=None,
        ),
    )

    with pytest.raises(RuntimeError, match="expected_alert_missing"):
        run_dast_evidence._require_evidence(report, public_requests=1)

    output = capsys.readouterr().err
    assert "public_seed=1" in output
    assert "public_alert=1" in output
    assert "ZAP/10020" in output
    assert "secret-must-not-log" not in output


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
    }
    assert upload["with"]["if-no-files-found"] == "error"
